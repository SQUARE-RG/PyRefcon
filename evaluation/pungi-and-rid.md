# Comparison with *Pungi* and *RID*

We compare the result of *PyRefcon* against *Pungi* and *RID*
literally through the comparison with *CpyChecker*
in their papers [^pungi][^rid].
The data of *Pungi* is extracted from Table 2 on page 100 and Table 3 on page 101;
whereas the data of *RID* is copied from Table 2 on page 542.

[^pungi]: Li, Siliang, and Gang Tan. "Finding reference-counting errors in Python/C programs with affine analysis." In ECOOP 2014–Object-Oriented Programming: 28th European Conference, Uppsala, Sweden, July 28–August 1, 2014. Proceedings 28, pp. 80-104. Springer Berlin Heidelberg, 2014.

[^rid]: Mao, Junjie, Yu Chen, Qixue Xiao, and Yuanchun Shi. "RID: finding reference count bugs with inconsistent path pair checking." In Proceedings of the Twenty-First International Conference on Architectural Support for Programming Languages and Operating Systems, pp. 531-544. 2016.

The number of true positives of *PyRefcon*, *CpyChecker*, and *Pungi*.

| Project   | *PyRefcon* | *CpyChecker* | *Pungi* |
|:--------- | ----------:| ------------:| -------:|
| pyaudio   | 42         | 25           | 30      |
| pycrypto  | 7          | 6            | 7       |
| pyxattr   | 2          | 2            | 2       |
| rrdtool   | 24         | 0            | 0       |
| dbus      | 9          | 1            | 1       |
| duplicity | 3          | 2            | 2       |
| Total     | 87         | 36           | 42      |

The number of true positives of *PyRefcon*, *CpyChecker*, and *RID*.

| Project   | *PyRefcon* | *CpyChecker* | *RID*   |
|:--------- | ----------:| ------------:| -------:|
| pyaudio   | 42         | 32           | 46      |

The corresponding results above is shown in Figure 9b.
