Time Overhead per Project
=========================

Time Consumption
----------------

The table below presents the time consumption of five executions measured under
a concurrency of 16 processes. Different from the average time of every file,
the time consumption presented below includes the overhead of the concurrent
job scheduler. The last column is shown in Column $T_{total}$ in Table 1 in the
paper.

| project    | run 1    | run 2    | run 3    | run 4    | run 5    | average   |
|:---------- | --------:| --------:| --------:| --------:| --------:| ---------:|
| pyaudio    | 1.176    | 1.179    | 1.180    | 1.189    | 1.197    | 1.18      |
| pycrypto   | 2.800    | 2.800    | 2.805    | 2.945    | 3.099    | 2.89      |
| pyxattr    | 1.524    | 1.531    | 1.535    | 1.542    | 1.554    | 1.54      |
| rrdtool    | 5.191    | 5.27     | 5.327    | 5.333    | 5.382    | 5.30      |
| dbus       | 5.863    | 5.927    | 6.411    | 6.47     | 6.568    | 6.25      |
| duplicity  | 0.198    | 0.199    | 0.199    | 0.199    | 0.215    | 0.20      |
| numpy      | 445.342  | 455.811  | 469.821  | 535.365  | 543.308  | 489.93    |
| scipy      | 509.267  | 557.094  | 600.203  | 626.292  | 648.097  | 588.19    |
| numba      | 8.774    | 8.904    | 9.655    | 12.407   | 12.443   | 10.44     |
| Pillow     | 57.799   | 59.081   | 65.483   | 78.225   | 79.12    | 67.94     |
| tensorflow | 6525.19  | 6639.115 | 7129.592 | 7216.329 | 8708.523 | 7,243.75  |
| pytorch    | 4352.381 | 4386.789 | 4715.479 | 4925.502 | 5296.262 | 4,735.28  |

* Sum time: 13,152.89 seconds

Memory Consumption
------------------

Table 1 in the paper presents the estimated upper bound of memory consumption
under a concurrency of 16 processes, which are measured with the sum
consumption of top 16 files. The data is automatically generated with function
`QUERY` of Google Spreadsheet.

Assume importing file `time-and-memory-file.csv` to Google Spreadsheet as a new
worksheet named `time-and-memory`. In another worksheet, the data is generated
with the formula below.

```
=SUM(QUERY('time-and-memory'!A2:N, "select N where A = '"&PROJECT_NAME&"' order by N desc limit 16"))/16
```

And the total upper bound of all files is generated with the formula below.

```
=SUM(QUERY('time-and-memory'!N2:N, "select N order by N desc limit 16"))/16
```

The output of the above formulas is shown below. When converting the output of
the formulas above to GiB unit by dividing 1024^2, the results in the last
column are shown in Column $M_{peak}$ in Table 1.

| project    | output     | =B1/1024/1024 |
| ---------- | ---------- | ------------- |
| pyaudio    | 14145.5    | 0.01          |
| pycrypto   | 345273.55  | 0.33          |
| pyxattr    | 19672.25   | 0.02          |
| rrdtool    | 28480.75   | 0.03          |
| dbus       | 482811.75  | 0.46          |
| duplicity  | 28494.75   | 0.03          |
| numpy      | 1111024.4  | 1.06          |
| scipy      | 979046.1   | 0.93          |
| numba      | 467547.35  | 0.45          |
| Pillow     | 574667.65  | 0.55          |
| tensorflow | 4828929.65 | 4.61          |
| pytorch    | 5291144.85 | 5.05          |
| total      | 5524082.5  | 5.27          |
