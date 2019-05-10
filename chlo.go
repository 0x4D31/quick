// Copyright (c) 2019, Adel "0x4d31" Karimi.
// All rights reserved.
// Licensed under the BSD 3-Clause license.
// For full license text, see the LICENSE file in the repo root
// or https://opensource.org/licenses/BSD-3-Clause

package quick

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type CHLO struct {
	QUICMessage
	MessageAuthHash []byte
	FrameType       byte
	FtStream        bool
	FtFIN           bool
	FtDataLength    uint8
	FtOffsetLength  uint8
	FtStreamLength  uint8
	StreamID        uint8
	DataLength      uint16
	Tag             string
	TagNumber       uint16
	TagValues        map[string]string
	TagsInOrder     []string
}

func (ch CHLO) String() string {
	str := fmt.Sprintf("Public Flags: %x\n", ch.PublicFlags)
	str += fmt.Sprintf("CID: %x\n", ch.CID)
	str += fmt.Sprintf("Version: %s\n", ch.Version)
	str += fmt.Sprintf("Packet Number: %d\n", ch.PacketNumber)
	str += fmt.Sprintf("Message Authentication Hash: %x\n", ch.MessageAuthHash)
	str += fmt.Sprintf("Frame Type: %x\n", ch.FrameType)
	str += fmt.Sprintf("Stream ID: %d\n", ch.StreamID)
	str += fmt.Sprintf("Data Length: %d\n", ch.DataLength)
	str += fmt.Sprintf("Tag: %s\n", ch.Tag)
	str += fmt.Sprintf("Tag Number: %d\n", ch.TagNumber)
	str += fmt.Sprintf("SNI: %q\n", ch.TagValues["SNI"])
	str += fmt.Sprintf("UAID: %q\n", ch.TagValues["UAID"])
	str += fmt.Sprintf("Tags in Order: %q\n", ch.TagsInOrder)
	str += fmt.Sprintln("Tag Values:", ch.TagValues)
	return str
}

func (ch *CHLO) DecodeCHLO(payload []byte) error {
	ch.Raw = payload
	// Only process CHLO packets
	if !(bytes.Contains(payload, []byte("CHLO"))) {
		return ErrWrongType
	}
	// Public Flags
	ch.PublicFlags = payload[0]
	ch.PfVersion = payload[0]&0x01 != 0             // Version
	ch.PfReset = payload[0]&0x02 != 0               // Reset
	ch.PfDivNonce = payload[0]&0x04 != 0            // Diversification Nonce
	ch.PfCIDLen = payload[0]&0x08 != 0              // CID Length
	ch.PfPacketNumLen = (payload[0]&0x30 >> 4) + 1  // Packet Number Length in bytes
	ch.PfMultipath = payload[0]&0x40 != 0           // Multipath
	ch.PfReserved = payload[0]&0x80 != 0            // Reserved
	if ch.PublicFlags == 0 {
		return ErrBadPFlags
	}
	hs := payload[1:]
	// CID Length
	if ch.PfCIDLen {
		ch.CID = hs[0:8]
		hs = hs[8:]
	}
	// Version
	if ch.PfVersion {
		ch.Version = string(hs[0:4])
		hs = hs[4:]
	}
	// Packet Number Length
	switch ch.PfPacketNumLen {
	case 1:
		ch.PacketNumber = uint(hs[0])
	case 2:
		ch.PacketNumber = uint(binary.BigEndian.Uint16(hs[0:2]))
	case 3:
		ch.PacketNumber = (uint(hs[0])<<16) | (uint(hs[1])<<8) | uint(hs[2])
	}
	hs = hs[ch.PfPacketNumLen:]
	// Message Authentication Hash
	ch.MessageAuthHash = hs[0:12]
	// Frame Type
	ch.FrameType = hs[12]
	ch.FtStream = hs[12]&0x80 != 0             // STREAM
	ch.FtFIN = hs[12]&0x40 != 0                // FIN
	ch.FtDataLength = (hs[12]&0x20  >> 5) + 1  // Data Length in bytes
	ch.FtOffsetLength = hs[12]&0x1C >> 2       // Offset Length
	ch.FtStreamLength = hs[12]&0x3             // Stream Length
	ch.StreamID = uint8(hs[13])                // Stream ID
	// Data Length
	if ch.FtDataLength == 2 {
		ch.DataLength = binary.BigEndian.Uint16(hs[14:16])
	} else {
		return ErrBadFtDLen
	}
	if len(hs[16:]) < int(ch.DataLength) {
		return ErrBadLength
	}
	// Tag: CHLO (Client Hello)
	ch.Tag = string(hs[16:20])
	if ch.Tag != "CHLO" {
		return ErrWrongType
	}
	// Tag Number
	ch.TagNumber = binary.LittleEndian.Uint16(hs[20:22])
	hs = hs[24:]  // Padding: 0000
	if len(hs) < 2 {
		return ErrBadLength
	}
	// Tag/Values
	ch.TagValues = make(map[string]string)
	TagsOffsetEnd := make(map[string]uint32)
	// Extract tags offset end
	for i := 0; i < int(ch.TagNumber); i++ {
		var TagName string
		TempTag := hs[0:4]
		if TempTag[3] == 0 {
			TagName = string(TempTag[0:3])
		} else {
			TagName = string(TempTag[0:4])
		}
		TagsOffsetEnd[TagName] = binary.LittleEndian.Uint32(hs[4:8])
		ch.TagsInOrder = append(ch.TagsInOrder, TagName)
		hs = hs[8:]
	}
	for i, tag := range ch.TagsInOrder {
		// Calculate the tag length
		var TagLen uint32
		if i == 0 {
			TagLen = TagsOffsetEnd[tag]
		} else {
			TagLen = TagsOffsetEnd[tag] - TagsOffsetEnd[ch.TagsInOrder[i-1]]
		}
		// Extract the intended tag/values
		switch tag {
		case "SNI", "UAID", "AEAD", "KEXS", "VER", "PDMD", "COPT":
			ch.TagValues[tag] = string(hs[0:TagLen])
		case "PAD":  //do nothing
		default:
			ch.TagValues[tag] = hex.EncodeToString(hs[0:TagLen])
		}
		hs = hs[TagLen:]
	}

	return nil
}
