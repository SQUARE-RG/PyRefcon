PyRefcon
========

Experimental Results
--------------------

The detailed experimental results are provided in directory `evaluation`. We
present statistics and tables in CSV format, which can be clearly viewed with
spreadsheet editors like MS Excel, and LibreOffice Calc, or in Linux shell with
command `column -t -s, input.csv | less -S`.

### Bug Reports of *PyRefcon*

`evaluation/pyrefcon-reports.csv` shows the detailed information of each bug
report generated by `PyRefcon`, where the corresponding bug reports in HTML
format is presented in directory `pyrefcon-reports`.

In the sheet, column *project* shows the name of the benchmark instance. Column
*bug type* presents the type of the reported bug, where *RL*, *UaR* represent
bug type *Reference Leak* and *Use-after-Release* mentioned in Section 2.3. The
next four columns provide the location (file, function, and line number) and
path length of the report. The file name of the bug report is presented in the
next column, and the corresponding HTML bug report file can be found from path
`evaluation/pyrefcon-reports/<project>/report-xxxxxx.html`. Column *result* presents
the result of manual bug report revision, where *TP* and *FP* denote
true-positive and false-positive respectively. Column *category* provides the
category of the report that we assigned, where the type of true positives are
shown in Section 5.5, and reasons of false positives are shown in Section 5.2.
If the bug report is submitted to developers, the link to the corresponding
issue and its current status are presented in column *issue* and *submit*.
Otherwise, the reason why it is not submitted is presented in column *submit*.
In the last column, the number of similar reports is presented. If the number
is greater than 1, it means there are redundant bug reports for it.

### Bug Reports of *CpyChecker*

As mentioned in Section 5.1 and 5.3, we execute *CpyChecker* on the same
benchmark we used, where the information of the bug reports generated by
*CpyChecker* is presented in file `evaluation/cpychecker-reports.csv`.

In the sheet, all columns, except the last column, represent the same meaning
as the corresponding columns in file `evaluation/pyrefcon-reports.csv`. The HTML
bug report files presented in column *report* are stored in path
`evaluation/cpychecker-reports/<project>/xxxxxx.html`.  And the last column shows
whether the report is a *unique* report that *PyRefcon* does not report, or it
is a *common* report that *PyRefcon* also reports. The common true positives
comparison of *PyRefcon* and *CpyChecker* is shown in Figure 9a.

### Comparison with *Pungi* and *RID*

In Section 5.3, we also mentioned the literal comparison with *Pungi* and *RID*
through their comparisons with *CpyChecker*. The detailed information of this
comparison shown in Figure 9b is presented in file
`evaluation/pungi-and-rid.md`.

### Resource Consumption of *PyRefcon*

In section 5.4, we mentioned about average time and memory consumption per kilo
line of code. The average data is computed based on the measurement on every
translation unit, which is shown in file `evaluation/time-and-memory-file.csv`.

The first two columns in the sheet present the project name and the main file
of the translation unit. The following ten columns denote the time (in seconds)
and memory (in KiB) consumption of five executions. And the average of the five
executions are shown in the last two columns for time and memory.

Besides, in Table 1 on page 7, we mentioned measured time consumption and the
estimated upper bound of memory consumption of each project under a concurrency
of 16 analyzer instances. The intermediate data of execution time and
measurement procedure of memory are illustrated in file
`evaluation/time-and-memory-project.md`
