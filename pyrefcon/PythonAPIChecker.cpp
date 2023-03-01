#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

#define dbp llvm::outs()

namespace {
class ObjectRefCountInfo {
public:
  ObjectRefCountInfo() = default;
  ObjectRefCountInfo(long RC) : RefCount(RC) {}

  auto getRefCount() const {
    assert(!isBorrowed() && !isRelinqished());
    return RefCount;
  }
  bool isNonZero() const { return RefCount; }
  bool isZero() const { return !RefCount; }
  bool isOne() const { return 1 == RefCount; }
  bool isNegOne() const { return -1 == RefCount; }
  bool isReleased() const { return isZero() || isNegOne(); }
  bool isBorrowed() const { return brwRefCnt == RefCount; }
  bool isBR() const { return isBorrowed() || isRelinqished(); }
  bool isRelinqished() const { return relinqRefCnt == RefCount; }

  ObjectRefCountInfo inc() const {
    if (isRelinqished())
      return relinquished();
    return isBorrowed() ? 1 : RefCount + 1;
  }
  ObjectRefCountInfo dec() const {
    if (isRelinqished())
      return relinquished();
    assert(!isBorrowed());
    return RefCount - 1;
  }

  bool operator==(const ObjectRefCountInfo &o) const {
    return RefCount == o.RefCount;
  }
  bool operator!=(const ObjectRefCountInfo &o) const {
    return RefCount != o.RefCount;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(RefCount); }
  static ObjectRefCountInfo borrowed() { return {brwRefCnt}; }
  static ObjectRefCountInfo relinquished() { return {relinqRefCnt}; }

  static const long brwRefCnt = std::numeric_limits<long>::max();
  static const long relinqRefCnt = std::numeric_limits<long>::min();

private:
  long RefCount = 0;
};

raw_ostream &operator<<(raw_ostream &OS, const ObjectRefCountInfo &RC) {
  if (RC.isBorrowed())
    return OS << "borrowed";
  if (RC.isRelinqished())
    return OS << "relinqushed";
  return OS << RC.getRefCount();
}
} // namespace

// Mapping an PyObject * to its reference count.
// As PyObject cannot be used directly via its value, it should be a counjured
// symbol or other symbolic exprs.
REGISTER_MAP_WITH_PROGRAMSTATE(ObjectRefCount, SymbolRef, ObjectRefCountInfo)
REGISTER_SET_WITH_PROGRAMSTATE(EscapedObject, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(StolenObject, SymbolRef)
REGISTER_MAP_WITH_PROGRAMSTATE(MonitorAssign, const MemRegion *, SymbolRef)

namespace {
class PythonAPIChecker
    : public Checker<check::Bind, check::DeadSymbols, check::Location,
                     check::PostCall, eval::Assume, eval::Call,
                     check::PreStmt<ReturnStmt>, check::PreCall,
                     check::PointerEscape> {
  mutable std::unique_ptr<BugType> BT_NonZeroDead, BT_ZeroReference,
      BT_ZeroReference_Stolen, BT_DecBorrowed, BT_DecEscaped, BT_ManualRefCnt,
      EI_RefCnt;

  static ProgramStateRef setReferenceCount(ProgramStateRef State,
                                           SymbolRef Object,
                                           ObjectRefCountInfo RC) {
    dbp << "bind " << Object << " = " << RC << '\n';
    return State->set<ObjectRefCount>(Object, RC);
  }

  static ProgramStateRef dropReferenceCount(ProgramStateRef State,
                                            SymbolRef Object) {
    State = State->remove<EscapedObject>(Object);
    State = State->remove<StolenObject>(Object);
    return State->remove<ObjectRefCount>(Object);
  }

  static ProgramStateRef escapeObject(ProgramStateRef State, SymbolRef Object) {
    if (isObjectRelinquished(State, Object))
      return State;
    dbp << "escape: " << Object << '\n';
    return State->add<EscapedObject>(Object);
  }

  static ProgramStateRef stealObject(ProgramStateRef State, SymbolRef Object) {
    if (isObjectRelinquished(State, Object))
      return State;
    return State->add<StolenObject>(Object);
  }

  static ProgramStateRef relinquishObject(ProgramStateRef State,
                                          SymbolRef Object) {
    dbp << "relinq: " << Object << '\n';
    State = State->remove<EscapedObject>(Object);
    State = State->remove<StolenObject>(Object);
    return State->set<ObjectRefCount>(Object,
                                      ObjectRefCountInfo::relinquished());
  }

  void reportPySys_AuditWithN(const CallEvent &Call, CheckerContext &C) const;
  void reportNonZeroDead(ProgramStateRef State, SymbolRef Object,
                         CheckerContext &C) const;
  void reportZeroReference(SymbolRef Object, const Stmt *S,
                           CheckerContext &C) const;
  void reportDecreaseBorrowed(SymbolRef Object, const Stmt *S,
                              CheckerContext &C, bool isSteal) const;
  void reportManuallySettingReferenceCount(const Stmt *S,
                                           CheckerContext &C) const;

public:
  static bool isObjectEscaped(ProgramStateRef State, SymbolRef Object) {
    return State->get<EscapedObject>().contains(Object);
  }

  static bool isObjectStolen(ProgramStateRef State, SymbolRef Object) {
    return State->get<StolenObject>().contains(Object);
  }

  static bool isObjectRelinquished(ProgramStateRef State, SymbolRef Object) {
    auto *RC = State->get<ObjectRefCount>(Object);
    return RC ? RC->isRelinqished() : false;
  }

  static bool isObjectReleased(ProgramStateRef State, SymbolRef Object,
                               bool isMustReleased) {
    if (auto *C = dyn_cast_or_null<SymbolConjured>(Object)) {
      if (auto *RC = State->get<ObjectRefCount>(Object)) {
        if (C->getTag() == getTraceTag()) {
          if (RC->isZero())
            return true;
          if (isMustReleased)
            return false;
          int MonitorCount = 0;
          for (auto &MonitorObject : State->get<MonitorAssign>()) {
            if (MonitorObject.second == Object)
              ++MonitorCount;
          }
          return RC->getRefCount() == MonitorCount;
        }
        if (isMustReleased && RC->isNegOne() && !C->getTag())
          return true;
        if (!isMustReleased && RC->isReleased() && !C->getTag())
          return true;
      }
    }
    return false;
  }

  void printState(raw_ostream &OS, ProgramStateRef State, const char *NL,
                  const char *Sep) const override;
  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void evalRefCntPrinter(const CallEvent &Call, CheckerContext &C) const;
  void evalMonitorAssign(const CallEvent &Call, CheckerContext &C) const;
  void evalValueBuilder(const CallEvent &Call, CheckerContext &C,
                        unsigned FormatIdx, unsigned VaArgIdx) const;

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                     const InvalidatedSymbols &Escaped,
                                     const CallEvent *Call,
                                     PointerEscapeKind Kind) const;

  void checkIncDecFunctions(SVal Loc, const Stmt *S, CheckerContext &C) const;

  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, SVal, bool) const;

  void checkUseAfterRelease(SymbolRef Object, const Stmt *S,
                            CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *R, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkBindingReleased(SVal Loc, SVal Val, const Stmt *S,
                            CheckerContext &C) const;

  void checkIncDecBind(ProgramStateRef State, SymbolRef Object,
                       const UnaryOperator *UO, CheckerContext &C) const;
  void evalReturnedObjectRefCnt(ProgramStateRef State, ObjectRefCountInfo RC,
                                const CallEvent &Call, CheckerContext &C) const;
  ProgramStateRef evalDecRefCount(ProgramStateRef State, SymbolRef Object,
                                  const Expr *E, CheckerContext &C,
                                  bool isSteal) const;

private:
  static bool checkIfIsPythonIncDecRefFunction(const Decl *D);
  static bool checkIfIsPyObjectRefCntField(const Decl *D);
  static bool checkIfIsPyObjectRefCntField(const Stmt *S);
  static bool checkIfIsPyObjectRefCntField(SVal V);
  static bool checkifIsTracedObject(SymbolRef Object);
  static const void *getTraceTag() {
    static int Tag = 42;
    return &Tag;
  }
  static Optional<StringRef> getSValAsStringConst(SVal V);
};
} // namespace

void ento::registerPythonReferenceCountingChecker(CheckerManager &mgr) {
  mgr.registerChecker<PythonAPIChecker>();
}

bool ento::shouldRegisterPythonReferenceCountingChecker(
    const CheckerManager &) {
  return true;
}

///////////////////////////////////////////////////////////////////////////////
//
// SEGTAG: Checking for values
//
///////////////////////////////////////////////////////////////////////////////

bool PythonAPIChecker::checkIfIsPythonIncDecRefFunction(const Decl *D) {
  if (auto *Callee = dyn_cast_or_null<FunctionDecl>(D))
    if (auto *CII = Callee->getIdentifier())
      if (CII->isStr("_Py_INCREF") || CII->isStr("_Py_DECREF") ||
          CII->isStr("_Py_XINCREF") || CII->isStr("_Py_XDECREF") ||
          CII->isStr("Py_IncRef") || CII->isStr("Py_DecRef"))
        return true;
  return false;
}

bool PythonAPIChecker::checkIfIsPyObjectRefCntField(const Decl *D) {
  if (auto *Field = dyn_cast_or_null<FieldDecl>(D))
    if (auto *FII = Field->getIdentifier())
      if (FII->isStr("ob_refcnt"))
        return true;
  return false;
}

bool PythonAPIChecker::checkIfIsPyObjectRefCntField(const Stmt *S) {
  if (auto *E = dyn_cast_or_null<Expr>(S))
    if (auto *ME = dyn_cast_or_null<MemberExpr>(E->IgnoreParenImpCasts()))
      return checkIfIsPyObjectRefCntField(ME->getMemberDecl());
  return false;
}

bool PythonAPIChecker::checkIfIsPyObjectRefCntField(SVal V) {
  if (auto X = V.getAs<loc::MemRegionVal>())
    if (auto *R = X->getAsRegion()->StripCasts())
      if (auto *FR = dyn_cast<FieldRegion>(R))
        return checkIfIsPyObjectRefCntField(FR->getDecl());
  return false;
}

bool PythonAPIChecker::checkifIsTracedObject(SymbolRef Object) {
  if (auto *CS = dyn_cast_or_null<SymbolConjured>(Object))
    return !CS->getTag() || CS->getTag() == getTraceTag();
  return false;
}

Optional<StringRef> PythonAPIChecker::getSValAsStringConst(SVal V) {
  auto *R = V.getAsRegion();
  if (!R)
    return {};
  while (auto *SR = dyn_cast<SubRegion>(R)) {
    if (auto *Str = dyn_cast<StringRegion>(SR))
      return Str->getStringLiteral()->getString();
    R = SR->getSuperRegion();
  }
  return {};
}

void PythonAPIChecker::printState(raw_ostream &OS, ProgramStateRef State,
                                  const char *NL, const char *Sep) const {
  auto ORC = State->get<ObjectRefCount>();
  if (ORC.isEmpty())
    return;

  std::map<SymbolRef, std::set<const MemRegion *>> Monitors;
  for (auto &MO : State->get<MonitorAssign>()) {
    Monitors[MO.second].emplace(MO.first);
  }

  auto ESC = State->get<EscapedObject>();
  auto STO = State->get<StolenObject>();
  OS << Sep << "PythonAPIChecker :" << NL;
  for (auto OR : ORC) {
    if (!OR.first)
      continue;
    OS << OR.first << (ESC.contains(OR.first) ? "*" : "")
       << (STO.contains(OR.first) ? "-" : "") << " = " << OR.second;
    auto OM = Monitors.find(OR.first);
    if (Monitors.end() == OM || OM->second.empty()) {
      OS << " {}" << NL;
      continue;
    }
    auto MI = OM->second.begin(), ME = OM->second.end();
    OS << " {" << *MI;
    for (++MI; MI != ME; ++MI) {
      OS << ", " << *MI;
    }
    OS << '}' << NL;
  }
}

void PythonAPIChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  checkBindingReleased(Loc, Val, S, C);
  checkIncDecFunctions(Loc, S, C);
}

ProgramStateRef PythonAPIChecker::checkPointerEscape(
    ProgramStateRef State, const InvalidatedSymbols &Escaped,
    const CallEvent *Call, PointerEscapeKind Kind) const {
  bool isRelinquish = false;
  if (PSK_DirectEscapeOnCall == Kind) {
    isRelinquish = true;
    if (Call)
      if (auto *FD = dyn_cast_or_null<FunctionDecl>(Call->getDecl()))
        if (auto *II = FD->getIdentifier()) {
          StringRef Name = II->getName();
          // Do not escape model and debug functions.
          if (Name.startswith("clang_analyzer_"))
            return State;
          auto Loc = FD->getCanonicalDecl()->getBeginLoc();
          // Do not escape undeclared functions.
          if (Loc.isInvalid())
            return State;
          // Do not escape un-modeled python functions. Apart from
          // PyObject_Free.
          if (FD->getASTContext().getSourceManager().isInSystemHeader(Loc) &&
              "PyObject_Free" != Name) {
            auto *MD = dyn_cast<CXXMethodDecl>(FD->getCanonicalDecl());
            if (!MD)
              return State;
            // Escape on container calls.
            auto hasMember = [](const CXXRecordDecl *RD,
                                StringRef Name) -> bool {
              const auto &II = RD->getASTContext().Idents.get(Name);
              return RD->hasMemberName(
                  RD->getASTContext().DeclarationNames.getIdentifier(&II));
            };
            auto *RD = MD->getParent();
            if (!hasMember(RD, "begin") && !hasMember(RD, "iterator") &&
                !hasMember(RD, "iterator_category"))
              return State;
          }
        }
  } else if (PSK_IndirectEscapeOnCall == Kind || PSK_EscapeOther == Kind) {
    // Impossible to be referenced again.
    isRelinquish = true;
  }

  for (SymbolRef S : Escaped) {
    bool isCurrentlyTraced = State->get<ObjectRefCount>(S);
    bool canBeTraced = checkifIsTracedObject(S);
    if (isRelinquish) {
      if (isCurrentlyTraced) {
        dbp << "escape.";
        State = relinquishObject(State, S);
      }
    } else {
      if (isCurrentlyTraced || canBeTraced)
        State = escapeObject(State, S);
    }
  }

  return State;
}

///////////////////////////////////////////////////////////////////////////////
//
// SEGTAG: BugReporterVisitor and bug reporters
//
///////////////////////////////////////////////////////////////////////////////

namespace {
class PrintReferenceCountVisitor : public BugReporterVisitor {
  SymbolRef Object = nullptr;
  PathDiagnosticLocation Loc;

public:
  PrintReferenceCountVisitor(SymbolRef Object, PathDiagnosticLocation Loc = {})
      : Object(Object), Loc(Loc) {}

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    ID.AddPointer(Object);
    Loc.Profile(ID);
  }

  // Add a note if the virtual refcnt is different from its predecessors.
  PathDiagnosticPieceRef VisitNode(const ExplodedNode *N, BugReporterContext &C,
                                   PathSensitiveBugReport &BR) override {
    if (const auto *RC = N->getState()->get<ObjectRefCount>(Object)) {
      for (const auto *Pred : N->preds()) {
        const auto *PredRC = Pred->getState()->get<ObjectRefCount>(Object);
        if (!PredRC || *RC != *PredRC) {
          SmallString<100> sbuf;
          llvm::raw_svector_ostream Msg(sbuf);
          Msg << "Setting reference count to " << *RC;
          PathDiagnosticLocation Loc = PathDiagnosticLocation::create(
              N->getLocation(), C.getSourceManager());
          auto Piece =
              std::make_shared<PathDiagnosticEventPiece>(Loc, Msg.str());
          Piece->setPrunable(false);
          return Piece;
        }
      }
    }
    return nullptr;
  }

  // Relocate the trigger event to allocate site.
  PathDiagnosticPieceRef getEndPath(BugReporterContext &C,
                                    const ExplodedNode *N,
                                    PathSensitiveBugReport &BR) override {
    return Loc.isValid() ? std::make_shared<PathDiagnosticEventPiece>(
                               Loc, BR.getDescription())
                         : nullptr;
  }
};
} // namespace

void PythonAPIChecker::reportPySys_AuditWithN(const CallEvent &Call,
                                              CheckerContext &C) const {
  if (!BT_NonZeroDead)
    BT_NonZeroDead = std::make_unique<BugType>(
        getCheckerName(), "Non-Zero Dead Object", "Python Memory Error");

  auto R = std::make_unique<BasicBugReport>(
      *BT_NonZeroDead,
      "Calling PySys_Audit with format contains 'N' may cause reference leaks.",
      PathDiagnosticLocation::createBegin(Call.getArgExpr(1),
                                          C.getSourceManager(),
                                          C.getCurrentAnalysisDeclContext()));

  C.emitReport(std::move(R));
}

void PythonAPIChecker::reportNonZeroDead(ProgramStateRef State,
                                         SymbolRef Object,
                                         CheckerContext &C) const {
  if (!BT_NonZeroDead)
    BT_NonZeroDead = std::make_unique<BugType>(
        getCheckerName(), "Non-Zero Dead Object", "Python Memory Error");

  SmallString<100> sbuf;
  llvm::raw_svector_ostream os(sbuf);
  const ObjectRefCountInfo *RC = C.getState()->get<ObjectRefCount>(Object);
  assert(RC && "Non-Zero dead symbol without a reference count info?");

  os << "PyObject ownership leak with reference count of " << *RC;
  PathDiagnosticLocation Loc;
  if (auto *SC = dyn_cast<SymbolConjured>(Object)) {
    Loc = PathDiagnosticLocation::createBegin(
        SC->getStmt(), C.getSourceManager(), C.getLocationContext());
  } else if (auto *RV = dyn_cast<SymbolRegionValue>(Object)) {
    auto *R = RV->getRegion()->getBaseRegion();
    if (auto *VR = dyn_cast<VarRegion>(R)) {
      Loc = PathDiagnosticLocation::create(VR->getDecl(), C.getSourceManager());
    } else if (auto *TR = dyn_cast<CXXTempObjectRegion>(R)) {
      Loc = PathDiagnosticLocation::createBegin(
          TR->getExpr(), C.getSourceManager(), C.getLocationContext());
    } else if (auto *SR = dyn_cast<CXXThisRegion>(R)) {
      Loc = PathDiagnosticLocation::create(SR->getValueType()->getAsTagDecl(),
                                           C.getSourceManager());
    }
  }

  if (!Loc.isValid())
    return;

  ExplodedNode *ErrorNode = C.generateNonFatalErrorNode(State);
  if (!ErrorNode)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT_NonZeroDead, os.str(), ErrorNode, Loc,
      C.getLocationContext()->getDecl());
  R->markInteresting(Object);
  R->addVisitor(std::make_unique<PrintReferenceCountVisitor>(Object, Loc));
  C.emitReport(std::move(R));
}

void PythonAPIChecker::reportZeroReference(SymbolRef Object, const Stmt *S,
                                           CheckerContext &C) const {
  ExplodedNode *ErrorNode = C.generateErrorNode();
  if (!ErrorNode)
    return;

  if (!BT_ZeroReference)
    BT_ZeroReference = std::make_unique<BugType>(
        getCheckerName(), "Access released PyObject", "Python Memory Error");
  if (!BT_ZeroReference_Stolen)
    BT_ZeroReference_Stolen = std::make_unique<BugType>(
        getCheckerName(), "Access released PyObject (with stolen reference)",
        "Python Memory Error");

  SmallString<100> sbuf;
  llvm::raw_svector_ostream os(sbuf);
  if (auto *RS = dyn_cast_or_null<ReturnStmt>(S)) {
    os << "Returning a PyObject whose ownership has been released";
  } else if (auto *CE = dyn_cast_or_null<CallExpr>(S)) {
    std::string FunName;
    if (auto *ND = dyn_cast_or_null<NamedDecl>(CE->getCalleeDecl()))
      FunName = ND->getQualifiedNameAsString();
    os << "Calling ";
    if (!FunName.empty())
      os << "function '" << FunName << "'";
    else
      os << "a function";
    os << " with a PyObject argument whose ownership has been released";
  } else if (auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO_Assign == BO->getOpcode())
      os << "Spreading a PyObject whose ownership has been released";
  } else if (auto *DS = dyn_cast_or_null<DeclStmt>(S)) {
    os << "Spreading a PyObject whose ownership has been released";
  } else {
    os << "Accessing a PyObject whose ownership has been released";
  }

  bool isStolen = isObjectStolen(C.getState(), Object);
  if (isStolen)
    os << " (with stolen reference)";

  auto R = std::make_unique<PathSensitiveBugReport>(
      isStolen ? *BT_ZeroReference_Stolen : *BT_ZeroReference, os.str(),
      ErrorNode);
  R->markInteresting(Object);
  R->addRange(S->getSourceRange());
  R->addVisitor(std::make_unique<PrintReferenceCountVisitor>(Object));
  C.emitReport(std::move(R));
}

void PythonAPIChecker::reportDecreaseBorrowed(SymbolRef Object, const Stmt *S,
                                              CheckerContext &C,
                                              bool isSteal) const {
  ExplodedNode *ErrorNode = C.generateErrorNode();
  if (!ErrorNode)
    return;

  if (!BT_DecBorrowed)
    BT_DecBorrowed = std::make_unique<BugType>(
        getCheckerName(), "Decrease borrowed reference", "Python Memory Error");

  PathDiagnosticLocation Loc;
  const Decl *D = nullptr;
  if (const auto *LCtx = C.getStackFrame()) {
    if (const auto *CE = LCtx->getCallSite()) {
      Loc = PathDiagnosticLocation::createBegin(CE, C.getSourceManager(), LCtx);
      D = LCtx->getParent()->getDecl();
    }
  }

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT_DecBorrowed,
      isSteal ? "Stealing borrowed reference"
              : "Decrease reference count for borrowed reference",
      ErrorNode, Loc, D);
  R->markInteresting(Object);
  R->addRange(S->getSourceRange());
  R->addVisitor(std::make_unique<PrintReferenceCountVisitor>(Object, Loc));
  C.emitReport(std::move(R));
}

void PythonAPIChecker::reportManuallySettingReferenceCount(
    const Stmt *S, CheckerContext &C) const {
  // Skip interpreter inlined functions, e.g. _Py_NewReference.
  if (C.getSourceManager().isInSystemHeader(S->getBeginLoc()))
    return;

  if (!BT_ManualRefCnt)
    BT_ManualRefCnt = std::make_unique<BugType>(
        getCheckerName(), "Manually setting reference count",
        "Python Memory Error");

  auto R = std::make_unique<BasicBugReport>(
      *BT_ManualRefCnt, "Manually setting reference count via assignment",
      PathDiagnosticLocation::createBegin(S, C.getSourceManager(),
                                          C.getCurrentAnalysisDeclContext()));
  C.emitReport(std::move(R));
}

///////////////////////////////////////////////////////////////////////////////
//
// SEGTAG: Setting refcnt
//
///////////////////////////////////////////////////////////////////////////////

// Check and do dec operation on refcnt.
ProgramStateRef PythonAPIChecker::evalDecRefCount(ProgramStateRef State,
                                                  SymbolRef Object,
                                                  const Expr *E,
                                                  CheckerContext &C,
                                                  bool isSteal) const {
  assert(checkifIsTracedObject(Object));

  auto *RCOld = State->get<ObjectRefCount>(Object);

  if (RCOld && RCOld->isBorrowed()) {
    reportDecreaseBorrowed(Object, E, C, isSteal);
    return nullptr;
  }

  if (isSteal)
    State = stealObject(State, Object);

  return setReferenceCount(State, Object,
                           RCOld ? RCOld->dec() : ObjectRefCountInfo(-1));
}

// If we are in Py_INCREF or Py_DECREF, directly change the virtual refcnt.
void PythonAPIChecker::checkIncDecBind(ProgramStateRef State, SymbolRef Object,
                                       const UnaryOperator *UO,
                                       CheckerContext &C) const {
  assert(checkifIsTracedObject(Object));

  if (UO->isIncrementOp()) {
    if (const auto *RCOld = State->get<ObjectRefCount>(Object)) {
      State = setReferenceCount(State, Object, RCOld->inc());
    } else /* Conjured symbol from non-modeled functions. */ {
      State = setReferenceCount(State, Object, ObjectRefCountInfo(1));
    }
    C.addTransition(State);
    return;
  }

  if (UO->isDecrementOp()) {
    State = evalDecRefCount(State, Object, UO, C, /*isSteal=*/false);
    if (State)
      C.addTransition(State);
    return;
  }

  llvm_unreachable("Invalid unary operator kind in Py_INCREF or Py_DECREF");
}

// Set new refcnt.
void PythonAPIChecker::checkIncDecFunctions(SVal Loc, const Stmt *S,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SymbolRef Object = Loc.getLocSymbolInBase();
  if (/* Not a symbolic object in base */ !Object ||
      /* Not storing the ob_refcnt field */ !checkIfIsPyObjectRefCntField(Loc))
    return;
  if (/* Is an external object */ !checkifIsTracedObject(Object)) {
    dbp << "skip binding: " << Object << '\n';
    return;
  }

  if (!checkIfIsPythonIncDecRefFunction(C.getLocationContext()->getDecl())) {
    reportManuallySettingReferenceCount(S, C);
    return;
  }

  // If a (possibly) traced object is null, relinq it directly without checking
  // its reference count.
  // The assume below will also relinquish all other traced null objects.
  auto BaseV = C.getSValBuilder().makeLoc(Object);
  ProgramStateRef NonNull, Null;
  std::tie(NonNull, Null) = State->assume(BaseV);
  if (!NonNull) {
    assert(Null && "Both NonNull and Null are infeasible?");
    dbp << "nullptr.";
    State = relinquishObject(Null, Object);
    C.addTransition(State);
    return;
  }

  checkIncDecBind(NonNull, Object, cast<UnaryOperator>(S), C);
}

///////////////////////////////////////////////////////////////////////////////
//
// SEGTAG: Check leaks
//
///////////////////////////////////////////////////////////////////////////////

// Check for non-zero refcnt leak.
void PythonAPIChecker::checkDeadSymbols(SymbolReaper &SR,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  auto ObjectRefCountMap = State->get<ObjectRefCount>();

  std::set<SymbolRef> MarkedLive;
  for (auto &MO : State->get<MonitorAssign>()) {
    SymbolRef Obj = MO.second;
    if (!Obj && SR.isDead(Obj)) {
      SR.markLive(Obj);
      MarkedLive.emplace(Obj);
      dbp << "Mark live: " << Obj << " via " << MO.first << '\n';
    }
  }

  for (auto OR : ObjectRefCountMap) {
    if (!OR.first || !SR.isDead(OR.first) ||
        MarkedLive.find(OR.first) != MarkedLive.end())
      continue;
    bool Escaped = isObjectEscaped(State, OR.first);
    State = dropReferenceCount(State, OR.first);

    if (!isObjectReleased(C.getState(), OR.first, /*isMustReleased=*/false) &&
        !OR.second.isBR() && !Escaped) {
      // Report non-zero reference count and dead symbol.
      reportNonZeroDead(State, OR.first, C);
    }
  }

  C.addTransition(State);
}

// Stop tracking the objects assumed to NULL.
ProgramStateRef PythonAPIChecker::evalAssume(ProgramStateRef State, SVal V,
                                             bool A) const {
  auto RC = State->get<ObjectRefCount>();
  for (auto Obj : RC) {
    ConstraintManager &CMgr = State->getConstraintManager();
    if (CMgr.isNull(State, Obj.first).isConstrainedTrue()) {
      dbp << "nullptr.";
      State = relinquishObject(State, Obj.first);
    }
  }
  return State;
}

///////////////////////////////////////////////////////////////////////////////
//
// SEGTAG: Modeling new / borrow / steal reference
//
///////////////////////////////////////////////////////////////////////////////

// Mark the return value of clang analyzer new/borrow reference.
void PythonAPIChecker::evalReturnedObjectRefCnt(ProgramStateRef State,
                                                ObjectRefCountInfo RC,
                                                const CallEvent &Call,
                                                CheckerContext &C) const {
  assert(RC.isOne() || RC.isBorrowed());
  SymbolRef Object = Call.getReturnValue().getLocSymbolInBase();

  // Reset return values for model function calls.
  if (const auto *LCtx = C.getStackFrame()) {
    if (const auto *CE = dyn_cast_or_null<CallExpr>(LCtx->getCallSite())) {
      SVal RetV = C.getSValBuilder().conjureSymbolVal(getTraceTag(), CE, LCtx,
                                                      C.blockCount());
      State = State->BindExpr(Call.getOriginExpr(), Call.getLocationContext(),
                              RetV);
      Object = RetV.getAsSymbol();
    }
  }

  assert(Object && "Not a symbol?");
  auto *Callee = dyn_cast_or_null<NamedDecl>(C.getLocationContext()->getDecl());
  dbp << (Callee ? Callee->getQualifiedNameAsString() : "<unknown>") << ": ";
  State = setReferenceCount(State, Object, RC);
  C.addTransition(State);
}

// Set refcnt to 1 for the functions returning PyObject need to be decreased.
void PythonAPIChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const auto *II = Call.getCalleeIdentifier();
  if (!II)
    return;

  ProgramStateRef State = C.getState();

  if (II->isStr("clang_analyzer_PyObject_New_Reference")) {
    evalReturnedObjectRefCnt(State, 1, Call, C);
    return;
  }

  if (II->isStr("clang_analyzer_PyObject_Borrow_Reference")) {
    evalReturnedObjectRefCnt(State, ObjectRefCountInfo::borrowed(), Call, C);
    return;
  }

  // Decreasing refcnt for a borrowed object is not allowed, however it is
  // allowed for a returned object from unmodeled functions.
  if (II->isStr("clang_analyzer_PyObject_Steal_Reference")) {
    if (SymbolRef Object = Call.getArgSVal(0).getLocSymbolInBase())
      if (checkifIsTracedObject(Object)) {
        dbp << "steal ref: " << Object << '\n';
        C.getPredecessor()->getLocation().printJson(dbp);
        State = evalDecRefCount(State, Object, Call.getOriginExpr(), C,
                                /*isSteal=*/true);
        if (State)
          C.addTransition(State);
      }
    return;
  }

  if (II->isStr("PySys_Audit")) {
    if (auto FormatStr = getSValAsStringConst(Call.getArgSVal(1)))
      if (FormatStr->contains('N'))
        reportPySys_AuditWithN(Call, C);
    return;
  }

  if (II->isStr("Py_BuildValue") || II->isStr("_Py_BuildValue_SizeT")) {
    evalValueBuilder(Call, C, /*format=*/0, /*va_arg=*/0);
    return;
  }

  if (II->isStr("PyObject_CallFunction") ||
      II->isStr("_PyObject_CallFunction_SizeT")) {
    evalValueBuilder(Call, C, /*format=*/1, /*va_arg=*/1);
    return;
  }

  if (II->isStr("PyObject_CallMethod") ||
      II->isStr("_PyObject_CallMethod_SizeT") ||
      II->isStr("_PyObject_CallMethodId") ||
      II->isStr("_PyObject_CallMethodId_SizeT")) {
    evalValueBuilder(Call, C, /*format=*/2, /*va_arg=*/2);
    return;
  }
}

///////////////////////////////////////////////////////////////////////////////
//
// SEGTAG: Check use after refcnt = 0.
//
///////////////////////////////////////////////////////////////////////////////

void PythonAPIChecker::checkUseAfterRelease(SymbolRef Object, const Stmt *S,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (isObjectReleased(State, Object, /*isMustReleased=*/true) &&
      !isObjectEscaped(State, Object))
    reportZeroReference(Object, S, C);
}

// When loading from a symbolic location.
void PythonAPIChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (SymbolRef L = Loc.getLocSymbolInBase())
    checkUseAfterRelease(L, S, C);
}

// When returning from a function via return value.
void PythonAPIChecker::checkPreStmt(const ReturnStmt *R,
                                    CheckerContext &C) const {
  if (R)
    if (const Expr *E = R->getRetValue())
      if (SymbolRef Object = C.getSVal(E).getLocSymbolInBase())
        checkUseAfterRelease(Object, R, C);
}

// When calling a function via arguments.
void PythonAPIChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl()))
    if (auto *II = FD->getIdentifier())
      if (II->getName().startswith("clang_analyzer_"))
        return;

  for (int I = 0, E = Call.getNumArgs(); E != I; ++I)
    if (SymbolRef Object = Call.getArgSVal(I).getLocSymbolInBase())
      checkUseAfterRelease(Object, Call.getOriginExpr(), C);
}

// When assiged to another pointer.
void PythonAPIChecker::checkBindingReleased(SVal Loc, SVal Val, const Stmt *S,
                                            CheckerContext &C) const {
  SymbolRef V = Val.getLocSymbolInBase();
  const MemRegion *R = Loc.getAsRegion();
  if (!V || !R)
    return;

  if (!R->hasStackStorage()) {
    checkUseAfterRelease(V, S, C);
  }
}

///////////////////////////////////////////////////////////////////////////////
//
// Functions modeled in engine.
//
///////////////////////////////////////////////////////////////////////////////

bool PythonAPIChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;
  auto *II = FD->getIdentifier();
  if (!II)
    return false;

  if (II->isStr("clang_analyzer_PyObject_Report_RefCnt")) {
    evalRefCntPrinter(Call, C);
    return true;
  }

  if (II->isStr("clang_analyzer_PyObject_Monitor_Assign")) {
    evalMonitorAssign(Call, C);
    return true;
  }

  return false;
}

void PythonAPIChecker::evalRefCntPrinter(const CallEvent &Call,
                                         CheckerContext &C) const {
  if (!EI_RefCnt)
    EI_RefCnt = std::make_unique<BugType>(getCheckerName(), "RefCnt", "Debug");

  auto *ErrNode = C.generateNonFatalErrorNode();
  if (!ErrNode)
    return;

  SmallString<100> sbuf;
  llvm::raw_svector_ostream ss(sbuf);
  ProgramStateRef State = C.getState();
  SymbolRef TracedObject = nullptr;
  if (Call.getNumArgs() != 1) {
    ss << "Should provide one argument";
  } else {
    SVal Arg0 = Call.getArgSVal(0);
    if (SymbolRef Object = Arg0.getLocSymbolInBase()) {
      if (auto *RC = State->get<ObjectRefCount>(Object)) {
        ss << Arg0 << " = " << *RC;
        TracedObject = Object;
      } else {
        ss << "Not traced: " << Arg0;
      }
    } else {
      ss << "Invalid Argument: " << Arg0;
    }
  }

  auto R =
      std::make_unique<PathSensitiveBugReport>(*EI_RefCnt, ss.str(), ErrNode);
  if (TracedObject) {
    R->markInteresting(TracedObject);
    R->addVisitor(std::make_unique<PrintReferenceCountVisitor>(TracedObject));
  }
  C.emitReport(std::move(R));

  C.addTransition(State, ErrNode);
}

void PythonAPIChecker::evalMonitorAssign(const CallEvent &Call,
                                         CheckerContext &Ctx) const {
  if (Call.getNumArgs() != 2) {
    dbp << "Invalid clang_analyzer_PyObject_Monitor_Assign declaration.\n";
    return;
  }
  ProgramStateRef State = Ctx.getState();

  const MemRegion *Monitor = Call.getArgSVal(0).getAsRegion();
  if (!Monitor) {
    dbp << "Calling monitor assignment with non-region " << Call.getArgSVal(0)
        << '\n';
    return;
  }

  SymbolRef Object = Call.getArgSVal(1).getLocSymbolInBase();
  if (!Object || !checkifIsTracedObject(Object) ||
      !State->get<ObjectRefCount>(Object)) {
    State = State->remove<MonitorAssign>(Monitor);
    dbp << "Monitor assign: " << Monitor << " -> nil\n";
    Ctx.addTransition(State);
    return;
  }

  State = State->set<MonitorAssign>(Monitor, Object);
  dbp << "Monitor assign: " << Monitor << " -> " << Object << '\n';
  Ctx.addTransition(State);
}

void PythonAPIChecker::evalValueBuilder(const CallEvent &Call,
                                        CheckerContext &Ctx, unsigned FormatIdx,
                                        unsigned Idx) const {
  auto FormatStr = getSValAsStringConst(Call.getArgSVal(FormatIdx));
  if (!FormatStr)
    return;

  dbp << "build value: " << *FormatStr << '\n';

  ProgramStateRef State = Ctx.getState();
  for (char C : *FormatStr) {
    if (isalpha(C)) {
      ++Idx;
      if ('N' == C) {
        SymbolRef Object = Call.getArgSVal(Idx).getLocSymbolInBase();
        if (checkifIsTracedObject(Object)) {
          State = evalDecRefCount(State, Object, Call.getOriginExpr(), Ctx,
                                  /*isSteal=*/true);
          if (!State)
            return;
        }
      }
    }
  }

  Ctx.addTransition(State);
}
