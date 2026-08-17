# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the pNFS Flexfile Version 2 Layout Driver kernel module
#
obj-$(CONFIG_PNFS_FLEXFILE_V2_LAYOUT) += nfs_layout_flexfilesv2.o
nfs_layout_flexfilesv2-y := flexfilesv2.o flexfilesv2xdr.o flexfilesv2dev.o \
			    flexfilesv2enc.o flexfilesv2_xor.o \
			    flexfilesv2_md.o flexfilesv2_rs.o \
			    flexfilesv2_mojette.o flexfilesv2_checksum.o \
			    flexfilesv2_xdr_chunk.o flexfilesv2_write.o \
			    flexfilesv2_lifecycle.o
nfs_layout_flexfilesv2-$(CONFIG_PNFS_FLEXFILE_V2_KUNIT_TEST) += \
			    flexfilesv2_kunit.o
