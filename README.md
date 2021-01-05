# FileRecovery
A python script to recover various file types from a disk image using file signatures and only the Standard Library.

## Supported File Types for Recovery
The following file types are currently able to be recovered:
* MPG
* PDF
* GIF
* JPG
* DOCX
* AVI
* PNG

## Usage
FileRecovery requires Python 3.8 (developed using Python 3.8.6)

FileRecovery accepts a disk image as an input and can be used as follows:\
```./FileRecovery diskimage.dd``` or ```python3 FileRecovery.py diskimage.dd```

FileRecovery outputs:
* Recovered files (placed in the working direcory)
* Generic file name
* Hex starting and ending offset within the disk image
* SHA-256 hash for each file
