#!/usr/bin/env python3
#
# FileRecovery.py
#
# Version 1.0 1/4/21
#
# Required input: disk image
# Developed using Python 3.8.6
#
# Usage: 
# ./FileRecovery.py diskimage.dd
# OR
# python3 FileRecovery.py diskimage.dd
#
# Current Supported Recovered File Types:
# MPG, PDF, GIF, JPG, DOCX, AVI, PNG
#
# Description:
# Recovers files from a disk image using regex searches for 
# haeader and footer patterns.
# Outputs file name, start offset, end offset, and sha-256 hash.

import re # used for regex queries
import struct # used to convert hex bytes to long integer
import binascii # used to convert hex strings to bytes
import argparse # parses command line arguments
import hashlib # used to calculate hashes
import sys # used to exit upon error

# List of file signatures
# 
# Each item in the list uses the following format:
# [file extension, header (in hex bytes), footer (in hex bytes)]
# 
# If None is in the place of the footer, this indicates that file type
# does not have a footer and other means (such as a file size)
# must be used to find the enod of the file.
# 
# If there are multiple types of headers/footers for a file type,
# multiple entries can be made in the signatures list.
signatures = [
              ['.mpg',  b'\x00\x00\x01\xB3.\x00', b'\x00\x00\x00\x01\xB7'],
              ['.mpg',  b'\x00\x00\x01\xBA.\x00', b'\x00\x00\x00\x01\xB9'],
              ['.pdf',  b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46\x0A'],
              ['.pdf',  b'\x25\x50\x44\x46', b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A'],
              ['.pdf',  b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46\x0A'],
              ['.pdf',  b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46'],
              ['.pdf',  b'\x25\x50\x44\x46', b'\x0D\x25\x25\x45\x4F\x46\x0D'],
              ['.bmp', b'\x42\x4D....\x00\x00\x00\x00', None],
              ['.gif', b'\x47\x49\x46\x38\x37\x61', b'\x00\x00\x3B'],
              ['.gif', b'\x47\x49\x46\x38\x39\x61', b'\x00\x00\x3B'],
              ['.jpg', b'\xFF\xD8\xFF\xE0', b'\xFF\xD9'],
              ['.jpg', b'\xFF\xD8\xFF\xE1', b'\xFF\xD9'],
              ['.jpg', b'\xFF\xD8\xFF\xE2', b'\xFF\xD9'],
              ['.jpg', b'\xFF\xD8\xFF\xE8', b'\xFF\xD9'],
              ['.jpg', b'\xFF\xD8\xFF\xDB', b'\xFF\xD9'],
              ['.docx', b'\x50\x4B\x03\x04\x14\x00\x06\x00', b'\x50\x4B\x05\x06'],
              ['.avi', b'\x52\x49\x46\x46....\x41\x56\x49\x20\x4C\x49\x53\x54', None],
              ['.png', b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82']
             ]

# 64 kb chunk size
BUF_SIZE = 65536

def main():
    # Command line parser
    parser = argparse.ArgumentParser()
    parser.add_argument("disk_image")
    args = parser.parse_args()
    if args is None:
        sys.exit()
         
    file_name = args.disk_image
    
    # List of header offsets already used
    headers = []
    # List of footer offsets already used
    footers = []

    # File counter
    count = 1

    # Open the file name from the command line argument
    # Read the file in binary
    file = open(file_name, "rb")
    b = file.read()
    file.close()

    # Skip flags that are used to ensure only valid files are carved
    # True = offsets not valid
    # False = offsets are valid
    head_skip = False
    foot_skip = False
    pdf_skip = False
    
    # Iterate through each of the file types in the signatures list
    for sig in signatures:
        # Compile a regex pattern using the hex bytes for the header
        reg_head = re.compile(sig[1])
       
       # Iterate through all matches for the header pattern
       # Source:
       # https://stackoverflow.com/questions/27697218/python-regex-search-for-hexadecimal-bytes
        for match_head in reg_head.finditer(b):
            # The offset is the start of the pattern match
            offset = match_head.start()

            head_skip = False
            # If we have already carved a file using this header offset,
            # then skip this offset (since it can't be valid)
            if offset in headers:
                head_skip = True # Indicates this is not a valid header offset and must be skipped

            # Get the contents of the file from the header offset to the end of file
            start = b[offset:]

            # If the file type is a pdf, the next pdf header (if any must)
            # must be found so that the correct EOF is used
            next_offset = 0
            if sig[0] == '.pdf' and head_skip is False:
                # Finds offset of next header match
                for match in reg_head.finditer(b[offset+1:]):
                    next_offset = match.start() + offset
                    break

            # We only need to find a footer if the header is valid,
            # which means the head_skip flag must be false
            if head_skip is False:
                # If this file type has a footer value,
                # then find the footer
                if sig[2] is not None:
                    # Compile a regex pattern using the hex bytes for the footer
                    reg_foot = re.compile(sig[2])
                    # Iterate through all matches for the footer pattern
                    # Only seraching from the current header offset and forward
                    for match_foot in reg_foot.finditer(start):
                        # The end offset is the end of the footer match
                        end = match_foot.end()
                        # Add the header offset to get the true offset within the image
                        end += offset

                        # Indicates whether or not the current pdf footer value is valid
                        pdf_skip = False
                        # Tracks the next footer offset
                        next_end = 0

                        # If the file type is pdf, the end offset must be verified,
                        # since pdf's can have multiple EOFs.
                        #
                        # The correct EOF will be the last footer match that does not
                        # go past the next pdf header start offset.
                        #
                        # If there are no more pdf headers, then the last footer in the
                        # iterator will be used.
                        if sig[0] == '.pdf':
                            
                            # Find next match for the footer pattern
                            # Only searches from the current footer offset and forward
                            for match in reg_foot.finditer(b[end:]):
                                next_end = match.start() + end
                                break
                            # If next_offset is not 0, then there
                            # is another pdf header match in the file
                            if next_offset != 0:
                                # If the current footer offset is greater than the 
                                # next pdf header start, this can't be a valid offset.
                                #
                                # So, the pdf_skip flag is set to True and the footer match
                                # loop is exited.
                                if end > next_offset:
                                    pdf_skip = True
                                    break
                                # If there is another footer match, check if the next
                                # footer is past the start of the next pdf header.
                                # 
                                # If the next footer match is past the start of the 
                                # next pdf header, then the current footer offset must be the
                                # valid EOF.
                                #
                                # So, exit the footer match for loop.
                                elif next_end != 0:
                                    if next_end > next_offset:
                                        break
                        # Add extra 18 bytes after footer for docx
                        elif sig[0] == '.docx':
                            end += 18
                            break
                        # If the file type is not pdf, then only
                        # the first footer match is needed.
                        #
                        # So, exit the footer match for loop.
                        else:
                            break
                # If the file type does not have a footer,
                # the file size must be calculated
                else:
                    # bmp file size is located 2 bytes from start of file
                    if sig[0] == '.bmp':
                        head = 2
                    # avi file size is located 4 bytes from start of file
                    elif sig[0] == '.avi':
                        head = 4
                    # Add the offset for the file size to start of header match
                    size_start = offset + head

                    # File size is 4 bytes
                    # Read each byte individually, convert to hex, chop of the '0x', fill with zeroes
                    # so there is always atleast 2 hex numbers per byte.
                    # Convert the hex numbers to a string and concatenate the strings together.
                    size = str(hex(b[size_start])[2:].zfill(2)) + str(hex(b[size_start+1])[2:]).zfill(2) + str(hex(b[size_start+2])[2:].zfill(2)) + str(hex(b[size_start+3])[2:].zfill(2))
                    # Convert the hex string to bytes
                    size_b = binascii.unhexlify(size)
                    # Convert the little endian bytes to a long
                    # The '<' indicates little endian, and the 'l' indicates a long
                    long_size = struct.unpack('<l', size_b)
                    # Add the file size to the header offset
                    end = offset + long_size[0]

                    # For avi files, 8 bytes must be added to account for the
                    # header and file size bytes
                    if sig[0] == '.avi':
                        end += 8

            # If we have already carved a file using this footer offset,
            # then skip this offset (since it can't be valid)
            foot_skip = False
            if end in footers:
                foot_skip = True # Indicates this is not a valid footer offset and must be skipped

            # If all skip flags are False, then the offsets are valid
            # So, carve the file, find the hash, and print file info
            if not (head_skip or foot_skip or pdf_skip):

                # Add the header and footer offsets to their lists
                headers.append(offset)
                footers.append(end)

                # Write the data from the header offset to the footer offset to a new file
                newfile = b[offset:end]
                # File name is controlled by the file counter and the
                # file extension specified in the signature
                name = 'file' + str(count) + sig[0]
                file_out = open(name, "wb")
                file_out.write(newfile)
                file_out.close()
                
                # Get sha256 hash of file
                file_hash = sha256_hash(name)
                
                # Increment file counter
                count += 1

                # Print file info
                print("\nFile Name: " + name)
                print("Starting Offset: " + hex(offset))
                print("End Offset: " + hex(end))
                print("SHA-256 Hash: " + file_hash)

# Scans through the file and generates the SHA-256 hash 
# in chunks of 64K using the hashlib function
# Source:
# https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
def sha256_hash(file):
    with open(file, "rb") as hashfile:
        data = hashfile.read(BUF_SIZE)
        hasher = hashlib.sha256(data)
        while data:
            data = hashfile.read(BUF_SIZE)
            hasher.update(data)
    return hasher.hexdigest()

if __name__ == "__main__":
    main()