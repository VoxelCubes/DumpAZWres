#!/usr/bin/env python3.6
"""
Extracts images from azw.res file type

Written by KevinH
Refactored and updated to Python 3 by Voxel

Dependencies:
    imghdr
"""

import sys

import os
import struct
import codecs
import argparse

import imghdr

def get_image_type(imgname, imgdata=None):
    imgtype = imghdr.what(imgname, imgdata)

    # horrible hack since imghdr detects jxr/wdp as tiffs
    if imgtype is not None and imgtype == "tiff":
        imgtype = "wdp"

    # imghdr only checks for JFIF or Exif JPEG files. Apparently, there are some
    # with only the magic JPEG bytes out there...
    # ImageMagick handles those, so, do it too.
    if imgtype is None:
        if imgdata[0:2] == b'\xFF\xD8':
            # Get last non-null bytes
            last = len(imgdata)
            while imgdata[last-1:last] == b'\x00':
                last -= 1
            # Be extra safe, check the trailing bytes, too.
            if imgdata[last-2:last] == b'\xFF\xD9':
                imgtype = "jpeg"
    return imgtype


def process_CRES(i, data, folder_name):
    data = data[12:]
    imgtype = get_image_type(None, data)
    if imgtype is None:
        print(f"        Warning: CRES Section {i} does not contain a recognised resource")
        imgtype = "dat"
    imgname = f"HDimage{i:05d}.{imgtype:s}"
    imgdir = os.path.join(".", folder_name)
    if not os.path.exists(imgdir):
        os.mkdir(imgdir)
    print(f"        Extracting HD image: {imgname} from section {i}")
    imgpath = os.path.join(imgdir, imgname)
    with open(imgpath, 'wb') as file:
        file.write(data)


# this is just guesswork so far, making big assumption that
# metavalue key numbers remain the same in the CONT EXTH
def dump_contexth(codec, extheader):
    # determine text encoding
    if extheader == '':
        return
    id_map_strings = {
        1 : 'Drm Server Id (1)',
        2 : 'Drm Commerce Id (2)',
        3 : 'Drm Ebookbase Book Id(3)',
        100 : 'Creator_(100)',
        101 : 'Publisher_(101)',
        102 : 'Imprint_(102)',
        103 : 'Description_(103)',
        104 : 'ISBN_(104)',
        105 : 'Subject_(105)',
        106 : 'Published_(106)',
        107 : 'Review_(107)',
        108 : 'Contributor_(108)',
        109 : 'Rights_(109)',
        110 : 'SubjectCode_(110)',
        111 : 'Type_(111)',
        112 : 'Source_(112)',
        113 : 'ASIN_(113)',
        114 : 'versionNumber_(114)',
        117 : 'Adult_(117)',
        118 : 'Price_(118)',
        119 : 'Currency_(119)',
        122 : 'fixed-layout_(122)',
        123 : 'book-type_(123)',
        124 : 'orientation-lock_(124)',
        126 : 'original-resolution_(126)',
        127 : 'zero-gutter_(127)',
        128 : 'zero-margin_(128)',
        129 : 'K8_Masthead/Cover_Image_(129)',
        132 : 'RegionMagnification_(132)',
        200 : 'DictShortName_(200)',
        208 : 'Watermark_(208)',
        501 : 'cdeType_(501)',
        502 : 'last_update_time_(502)',
        503 : 'Updated_Title_(503)',
        504 : 'ASIN_(504)',
        508 : 'Unknown_Title_Furigana?_(508)',
        517 : 'Unknown_Creator_Furigana?_(517)',
        522 : 'Unknown_Publisher_Furigana?_(522)',
        524 : 'Language_(524)',
        525 : 'primary-writing-mode_(525)',
        526 : 'Unknown_(526)',
        527 : 'page-progression-direction_(527)',
        528 : 'override-kindle_fonts_(528)',
        529 : 'Unknown_(529)',
        534 : 'Input_Source_Type_(534)',
        535 : 'Kindlegen_BuildRev_Number_(535)',
        536 : 'Container_Info_(536)', # CONT_Header is 0, Ends with CONTAINER_BOUNDARY (or Asset_Type?)
        538 : 'Container_Resolution_(538)',
        539 : 'Container_Mimetype_(539)',
        542 : 'Unknown_but_changes_with_filename_only_(542)',
        543 : 'Container_id_(543)',  # FONT_CONTAINER, BW_CONTAINER, HD_CONTAINER
        544 : 'Unknown_(544)',
    }
    id_map_values = {
        115 : 'sample_(115)',
        116 : 'StartOffset_(116)',
        121 : 'K8(121)_Boundary_Section_(121)',
        125 : 'K8_Count_of_Resources_Fonts_Images_(125)',
        131 : 'K8_Unidentified_Count_(131)',
        201 : 'CoverOffset_(201)',
        202 : 'ThumbOffset_(202)',
        203 : 'Fake_Cover_(203)',
        204 : 'Creator_Software_(204)',
        205 : 'Creator_Major_Version_(205)',
        206 : 'Creator_Minor_Version_(206)',
        207 : 'Creator_Build_Number_(207)',
        401 : 'Clipping_Limit_(401)',
        402 : 'Publisher_Limit_(402)',
        404 : 'Text_to_Speech_Disabled_(404)',
    }
    id_map_hexstrings = {
        209 : 'Tamper_Proof_Keys_(209_in_hex)',
        300 : 'Font_Signature_(300_in_hex)',
    }
    _length, num_items = struct.unpack('>LL', extheader[4:12])
    extheader = extheader[12:]
    pos = 0
    for _ in range(num_items):
        idt, size = struct.unpack('>LL', extheader[pos:pos+8])
        content = extheader[pos + 8: pos + size]
        if idt in list(id_map_strings.keys()):
            name = id_map_strings[idt]
            print(f'\n    Key: "{name}"\n        Value: "{str(content, codec)}"')
        elif idt in list(id_map_values.keys()):
            name = id_map_values[idt]
            if size == 9:
                value, = struct.unpack('B', content)
                print(f'\n    Key: "{name}"\n        Value: 0x{value:01x}')
            elif size == 10:
                value, = struct.unpack('>H', content)
                print(f'\n    Key: "{name}"\n        Value: 0x{value:02x}')
            elif size == 12:
                value, = struct.unpack('>L', content)
                print(f'\n    Key: "{name}"\n        Value: 0x{value:04x}')
            else:
                print("\nError: Value for %s has unexpected size of %s" % (name, size))
        elif idt in list(id_map_hexstrings.keys()):
            name = id_map_hexstrings[idt]
            print(f'\n    Key: "{name}"\n        Value: 0x{codecs.encode(content, "hex")}')
        else:
            print(f"\nWarning: Unknown metadata with id {idt} found")
            name = str(idt) + ' (hex)'
            print(f'\n    Key: "{name}"\n        Value: 0x{codecs.encode(content, "hex")}')
        pos += size
    return


def sorted_header_keys(mheader):
    hdrkeys = sorted(list(mheader.keys()), key=lambda akey: mheader[akey][0])
    return hdrkeys


class PalmDB:
    # important  palmdb header offsets
    unique_id_seed = 68
    number_of_pdb_records = 76
    first_pdb_record = 78

    def __init__(self, palmdata):
        self.data = palmdata
        self.nsec, = struct.unpack_from('>H', self.data, PalmDB.number_of_pdb_records)

    def get_secaddr(self, secno):
        secstart, = struct.unpack_from('>L', self.data, PalmDB.first_pdb_record+secno*8)
        if secno == self.nsec-1:
            secend = len(self.data)
        else:
            secend, = struct.unpack_from('>L', self.data, PalmDB.first_pdb_record+(secno+1)*8)
        return secstart, secend

    def read_section(self, secno):
        if secno < self.nsec:
            secstart, secend = self.get_secaddr(secno)
            return self.data[secstart:secend]
        return ''

    def get_numsections(self):
        return self.nsec


class HdrParser:
    cont_header = {
        'magic'               : (0x00, '4s', 4),
        'record_size'         : (0x04, '>L', 4),
        'type'                : (0x08, '>H', 2),
        'count'               : (0x0A, '>H', 2),
        'codepage'            : (0x0C, '>L', 4),
        'unknown0'            : (0x10, '>L', 4),
        'unknown1'            : (0x14, '>L', 4),
        'num_resc_recs'       : (0x18, '>L', 4),
        'num_wo_placeholders' : (0x1C, '>L', 4),
        'offset_to_hrefs'     : (0x20, '>L', 4),
        'unknown2'            : (0x24, '>L', 4),
        'title_offset'        : (0x28, '>L', 4),
        'title_length'        : (0x2C, '>L', 4)
    }

    cont_header_sorted_keys = sorted_header_keys(cont_header)

    def __init__(self, header, start):
        self.header = header
        self.start = start
        self.hdr = {}
        # set it up for the proper header version
        self.header_sorted_keys = HdrParser.cont_header_sorted_keys
        self.cont_header = HdrParser.cont_header

        # parse the header information
        for key in self.header_sorted_keys:
            (pos, formatting, _) = self.cont_header[key]
            if pos < 48:
                val, = struct.unpack_from(formatting, self.header, pos)
                self.hdr[key] = val if not isinstance(val, bytes) else codecs.decode(val, "utf-8")
        self.exth = self.header[48:]
        self.title_offset = self.hdr['title_offset']
        self.title_length = self.hdr['title_length']
        self.title = self.header[self.title_offset: self.title_offset + self.title_length]
        self.codec = 'windows-1252'
        self.codec_map = {
            1252 : 'windows-1252',
            65001: 'utf-8',
            }
        if self.hdr['codepage'] in list(self.codec_map.keys()):
            self.codec = self.codec_map[self.hdr['codepage']]
        self.title = codecs.decode(self.title, self.codec)

    def dump_header_info(self):
        for key in self.cont_header_sorted_keys:
            (pos, _, tot_len) = self.cont_header[key]
            if pos < 48:
                if key != 'magic':
                    fmt_string = "  Field: {0:20s}   Offset: 0x{1:3x}   Width:  {2}   Value: 0x{3:0" + str(tot_len) + "x}"
                else:
                    fmt_string = "  Field: {0:20s}   Offset: 0x{1:3x}   Width:  {2}   Value: {3}"
                print(fmt_string.format(key, pos, tot_len, self.hdr[key]))
        print(f"EXTH Region Length:  0x{len(self.exth):x}")
        print("EXTH MetaData\nTitle:")
        print(self.title)
        dump_contexth(self.codec, self.exth)


def main():
    print("DumpAZWRES v01")
    parser = argparse.ArgumentParser(description="Unpack HD images from Kindle .azw.res container file")
    parser.add_argument("input_file", help="Kindle HD image container file")
    parser.add_argument("output_folder", nargs="?", default="azwres_images", help="Default: azwres_images")
    args = parser.parse_args()

    try:
        # make sure it is really an hd container file
        with open(args.input_file, 'rb') as file:
            contdata = file.read()

        palmheader = contdata[0:78]
        ident = palmheader[0x3C:0x3C+8]
        if ident != b'RBINCONT':
            raise 'Error: invalid file format'

        palm = PalmDB(contdata)
        header = palm.read_section(0)
        del contdata

        print("\n\nFirst Header Dump from Section 0")
        hparser = HdrParser(header, 0)
        hparser.dump_header_info()
        del hparser

        # now dump a basic sector map of the palmdb
        num_sections = palm.get_numsections()
        dtmap = {
            "FONT": "FONT",
            "RESC": "RESC",
            "CRES": "CRES",
            "CONT": "CONT",
            b"\xa0\xa0\xa0\xa0": "Empty_Image/Resource_Placeholder",
            b"\xe9\x8e\r\n": "EOF_RECORD",
        }
        dtmap2 = {
            "kindle:embed" : "KINDLE:EMBED",
        }

        print("\nMap of Palm DB Sections")
        print("    Dec  - Hex : Description")
        print("    ---- - ----  -----------")
        for i in range(num_sections):
            data = palm.read_section(i)
            dlen = len(data)
            if dlen < 12:
                dtag = data[0:4 if dlen > 3 else dlen]
                dtext = data[0:12 if dlen > 11 else dlen]
            else:
                dtag = codecs.decode(data[0:4], "utf-8")
                dtext = codecs.decode(data[0:12], "utf-8")
            desc = ''
            if dtext in dtmap2.keys():
                desc = codecs.decode(data, "utf-8")
                linkhrefs = []
                hreflist = desc.split('|')
                for href in hreflist:
                    if href != "":
                        linkhrefs.append("        " +   href)
                desc = "\n" + "\n".join(linkhrefs)
            elif dtag in dtmap.keys():
                desc = dtmap[dtag]
                if dtag == "CONT":
                    desc = "Cont Header"
                elif dtag == "CRES":
                    process_CRES(i, data, args.output_folder)
            else:
                desc = dtext
            if desc != "CONT":
                print(f"    {i:04d} - {i:04x}: {desc} [{dlen:d}]")

    except Exception as e:
        sys.exit(f"Error: {e}")


if __name__ == '__main__':
    main()
    print("\nUnpacking successfully completed")
