# ti86-link

ti86-link is a link adapter solution for TI-86 graphic calculator, which allows transfer of data between the calculator and host PC. The host program has been developed with Linux in mind, but uses cross-platform libraries. Two flavours of hardware are supported: a simple Arduino based serial adapter and a custom USB adapter based on Objective Development's [V-USB](http://www.obdev.at/vusb/) firmware-only USB driver. Schematics and firmware can be found in the subdirectories.

## Feature set

* A subset of TI silent link protocol is implemented allowing transactions to be controlled by the host computer.
* Calculator backups are not supported.
* File upload and download uses Ti-86 Graph Link variable format.
* Simple screenshots can be downloaded into text files.
* Arduino or dedicated USB adapter.

## Links

* [Joe Clussman's description of the TI-86's link port](http://paperlined.org/EE/microcontrollers/pic/projects/portable_VT_terminal/ti_86_link_port/link86all.htm)
* [Tim Singer's and Roman Lievin's link protocol description](http://merthsoft.com/linkguide/ti86/index.html)
