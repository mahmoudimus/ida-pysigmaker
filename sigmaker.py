import ctypes
import enum
import re

import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import idaapi
import win32clipboard

import idc


SIGNATURE_REGEX = re.compile(r"\\x[0-9A-F]{2}")
SIGNATURE_REGEX_2 = re.compile(r"((?:0x[0-9A-F]{2})+)")


PLUGIN_NAME = "Signature Maker Python"
PLUGIN_VERSION = "1.0.3"


# Signature types and structures
class SignatureType(enum.Enum):
    IDA = 0
    x64Dbg = 1
    Signature_Mask = 2
    SignatureByteArray_Bitmask = 3


class SignatureByte:
    def __init__(self, value, isWildcard):
        self.value = value
        self.isWildcard = isWildcard


Signature = list[SignatureByte]


# Output functions
def BuildIDASignatureString(signature: Signature, doubleQM: bool = False) -> str:
    result = []
    # Build hex pattern
    for byte in signature:
        if byte.isWildcard:
            result.append("??" if doubleQM else "?")
        else:
            result.append(f"{byte.value:02X}")
        result.append(" ")
    str_result = "".join(result).rstrip()
    return str_result


def BuildByteArrayWithMaskSignatureString(signature: Signature) -> str:
    pattern = []
    mask = []
    # Build hex pattern
    for byte in signature:
        pattern.append(f"\\x{byte.value:02X}" if not byte.isWildcard else "\\x00")
        mask.append("x" if not byte.isWildcard else "?")
    return "".join(pattern) + " " + "".join(mask)


def BuildBytesWithBitmaskSignatureString(signature: Signature) -> str:
    pattern = []
    mask = []
    # Build hex pattern
    for byte in signature:
        pattern.append(f"0x{byte.value:02X}, " if not byte.isWildcard else "0x00, ")
        mask.append("1" if not byte.isWildcard else "0")
    pattern_str = "".join(pattern).rstrip(", ")
    mask_str = "".join(mask)[::-1]  # Reverse bitmask
    return pattern_str + " 0b" + mask_str


def FormatSignature(signature: Signature, sig_type: SignatureType) -> str:
    if sig_type == SignatureType.IDA:
        return BuildIDASignatureString(signature)
    elif sig_type == SignatureType.x64Dbg:
        return BuildIDASignatureString(signature, True)
    elif sig_type == SignatureType.Signature_Mask:
        return BuildByteArrayWithMaskSignatureString(signature)
    elif sig_type == SignatureType.SignatureByteArray_Bitmask:
        return BuildBytesWithBitmaskSignatureString(signature)
    return ""


# Utility functions
def AddByteToSignature(signature: Signature, address, wildcard: bool):
    byte = SignatureByte(ida_bytes.get_byte(address), wildcard)
    signature.append(byte)


def AddBytesToSignature(signature: Signature, address, count: int, wildcard: bool):
    for i in range(count):
        AddByteToSignature(signature, address + i, wildcard)


def TrimSignature(signature: Signature):
    while signature and signature[-1].isWildcard:
        signature.pop()


def SetClipboardText(text: str) -> bool:
    GMEM_MOVEABLE = 2

    if not text:
        return False

    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        hGlobal = ctypes.windll.kernel32.GlobalAlloc(GMEM_MOVEABLE, len(text) + 1)
        if not hGlobal:
            win32clipboard.CloseClipboard()
            return False

        text_mem = ctypes.windll.kernel32.GlobalLock(hGlobal)
        if not text_mem:
            ctypes.windll.kernel32.GlobalFree(hGlobal)
            win32clipboard.CloseClipboard()
            return False

        ctypes.memmove(text_mem, text.encode("utf-8"), len(text) + 1)
        ctypes.windll.kernel32.GlobalUnlock(hGlobal)

        win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, hGlobal)
        ctypes.windll.kernel32.GlobalFree(hGlobal)
        win32clipboard.CloseClipboard()

        return True
    except Exception as e:
        print(f"Failed to set clipboard text: {e}")
        return False


def GetRegexMatches(string: str, regex: re.Pattern, matches: list[str]) -> bool:
    matches.clear()
    matches.extend(re.findall(regex, string))
    return bool(matches)


class Unexpected(Exception):
    pass


# "Select action:\n"                                                      // Title
# "<Create unique Signature for current code address:R>\n"                // Radio Button 0
# "<Find shortest XREF Signature for current data or code address:R>\n"	// Radio Button 1
# "<Copy selected code:R>\n"                                              // Radio Button 2
# "<Search for a signature:R>>\n"                                         // Radio Button 3
class SignatureMakerForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            f"""BUTTON YES* OK
BUTTON CANCEL Cancel
{PLUGIN_NAME} v{PLUGIN_VERSION}
{{FormChangeCb}}
Select action:
<Create unique Signature for current code address:{{rCreateUniqueSig}}>
<Find shortest XREF Signature for current data or code address:{{rFindXRefSig}}>
<Copy selected code:{{rCopyCode}}>
<Search for a signature:{{rSearchSignature}}>{{rAction}}>

Output format:
<IDA Signature:{{rIDASig}}>
<x64Dbg Signature:{{rx64DbgSig}}>
<C Byte Array Signature + String mask:{{rByteArrayMaskSig}}>
<C Raw Bytes Signature + Bitmask:{{rRawBytesBitmaskSig}}>{{rOutputFormat}}>

Options:
<Wildcards for operands:{{cWildcardOperands}}>
<Continue when leaving function scope:{{cContinueOutside}}>{{cGroupOptions}}>

""",
            {
                "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                "rAction": F.RadGroupControl(
                    (
                        "rCreateUniqueSig",
                        "rFindXRefSig",
                        "rCopyCode",
                        "rSearchSignature",
                    )
                ),
                "rOutputFormat": F.RadGroupControl(
                    (
                        "rIDASig",
                        "rx64DbgSig",
                        "rByteArrayMaskSig",
                        "rRawBytesBitmaskSig",
                    )
                ),
                "cGroupOptions": F.ChkGroupControl(
                    ("cWildcardOperands", "cContinueOutside")
                ),
            },
        )

    def OnFormChange(self, fid):
        # Debug output for when the form changes
        # print(f"Form changed, fid: {fid}", self.rAction.id, self.rOutputFormat.id, self.cGroupOptions.id)
        if fid == self.rAction.id:
            print(f"Action [{fid}] rAction changed: {self.GetControlValue(self.rAction):06x}")
        elif fid == self.rOutputFormat.id:
            print(
                f"Action [{fid}] rOutputFormat changed: {self.GetControlValue(self.rOutputFormat):06x}"
            )
        elif fid == self.cGroupOptions.id:
            print(
                f"Action [{fid}] cGroupOptions changed: {self.GetControlValue(self.cGroupOptions):06x}"
            )
        else:
            print(">>fid:%d" % fid)
        return 1


# Plugin specific definitions
class PySigMaker(ida_idaapi.plugin_t):
    IS_ARM = False

    def run(self, arg):
        self.run_plugin()

    def run_plugin(self):
        # Check what processor we have
        PySigMaker.IS_ARM = self.IsARM()

        form = SignatureMakerForm()
        form.Compile()

        # Execute the form and get results
        ok = form.Execute()
        if ok:
            action = form.rAction.value
            output_format = form.rOutputFormat.value
            wildcard_operands = form.cGroupOptions.value & 1
            continue_outside_of_function = form.cGroupOptions.value & 2

        # Don't forget to free the form after execution
        form.Free()

        sig_type = SignatureType(output_format)

        if action == 0:
            # Find unique signature for current address
            ea = idc.get_screen_ea()
            idaapi.show_wait_box("Generating signature...")
            signatures = self.GenerateUniqueSignatureForEA(
                ea, wildcard_operands, continue_outside_of_function
            )
            self.PrintSignatureForEA(signatures, ea, sig_type)
            idaapi.hide_wait_box()

        elif action == 1:
            # Find XREFs for current selection, generate signatures up to 250 bytes length
            ea = idc.get_screen_ea()
            xref_signatures = []
            idaapi.show_wait_box(
                "Finding references and generating signatures. This can take a while..."
            )
            self.FindXRefs(
                ea,
                wildcard_operands,
                continue_outside_of_function,
                xref_signatures,
                250,
            )
            # Print top 5 shortest signatures
            self.PrintXRefSignaturesForEA(ea, xref_signatures, sig_type, 5)
            idaapi.hide_wait_box()

        elif action == 2:
            # Print selected code as signature
            start, end = ida_kernwin.read_range_selection(
                idaapi.get_current_viewer()
            )
            if start and end:
                idaapi.show_wait_box("Please stand by...")
                self.PrintSelectedCode(start, end, sig_type, wildcard_operands)
                idaapi.hide_wait_box()
            else:
                idc.msg("Select a range to copy the code\n")

        elif action == 3:
            # Search for a signature
            input_signature = idaapi.ask_str(
                "", idaapi.HIST_SRCH, "Enter a signature"
            )
            if input_signature:
                idaapi.show_wait_box("Searching...")
                self.SearchSignatureString(input_signature)
                idaapi.hide_wait_box()

    def IsARM(self) -> bool:
        return "ARM" in ida_idaapi.get_inf_structure().procname

    def GetOperandOffsetARM(self, instruction, operand_offset, operand_length):
        for op in instruction.ops:
            if op.type in {
                idaapi.o_mem,
                idaapi.o_far,
                idaapi.o_near,
                idaapi.o_phrase,
                idaapi.o_displ,
                idaapi.o_imm,
            }:
                operand_offset[0] = op.offb
                operand_length[0] = (
                    3 if instruction.size == 4 else 7 if instruction.size == 8 else 0
                )
                return True
        return False

    def GetOperand(self, instruction, operand_offset, operand_length):
        if self.IsARM():
            return self.GetOperandOffsetARM(instruction, operand_offset, operand_length)

        for op in instruction.ops:
            if op.type != idaapi.o_void and op.offb != 0:
                operand_offset[0] = op.offb
                operand_length[0] = instruction.size - op.offb
                return True
        return False

    def FindSignatureOccurences(self, ida_signature: str) -> list:
        binary_pattern = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(
            binary_pattern, ida_ida.cvar.inf.min_ea, ida_signature, 16
        )

        results = []
        ea = ida_ida.cvar.inf.min_ea
        while True:
            occurence = ida_bytes.bin_search(
                ea,
                ida_ida.cvar.inf.max_ea,
                binary_pattern,
                ida_bytes.BIN_SEARCH_NOCASE | ida_bytes.BIN_SEARCH_FORWARD,
            )
            if occurence == idaapi.BADADDR:
                return results
            results.append(occurence)
            ea = occurence + 1

    def IsSignatureUnique(self, ida_signature: str) -> bool:
        return len(self.FindSignatureOccurences(ida_signature)) == 1

    def GenerateUniqueSignatureForEA(
        self,
        ea,
        wildcard_operands,
        continue_outside_of_function,
        max_signature_length=1000,
        ask_longer_signature=True,
    ):
        if ea == idaapi.BADADDR:
            raise Unexpected("Invalid address")
        if not idaapi.is_code(ida_bytes.get_flags(ea)):
            raise Unexpected("Cannot create code signature for data")

        signature = []
        sig_part_length = 0
        current_function = idaapi.get_func(ea)
        current_address = ea

        while True:
            if idaapi.user_cancelled():
                raise Unexpected("Aborted")

            instruction = idaapi.insn_t()
            current_instruction_length = idaapi.decode_insn(
                instruction, current_address
            )
            if current_instruction_length <= 0:
                if not signature:
                    raise Unexpected("Failed to decode first instruction")

                idc.msg(
                    f"Signature reached end of executable code @ {current_address:X}\n"
                )
                signature_string = BuildIDASignatureString(signature)
                idc.msg(f"NOT UNIQUE Signature for {ea:X}: {signature_string}\n")
                raise Unexpected("Signature not unique")

            if sig_part_length > max_signature_length:
                if ask_longer_signature:
                    result = idaapi.ask_yn(
                        idaapi.ASKBTN_YES,
                        f"Signature is already at {len(signature)} bytes. Continue?",
                    )
                    if result == 1:  # Yes
                        sig_part_length = 0
                    elif result == 0:  # No
                        signature_string = BuildIDASignatureString(signature)
                        idc.msg(
                            f"NOT UNIQUE Signature for {ea:X}: {signature_string}\n"
                        )
                        raise Unexpected("Signature not unique")
                    else:  # Cancel
                        raise Unexpected("Aborted")
                else:
                    raise Unexpected("Signature exceeded maximum length")

            sig_part_length += current_instruction_length

            operand_offset = [0]
            operand_length = [0]
            if (
                wildcard_operands
                and self.GetOperand(instruction, operand_offset, operand_length)
                and operand_length[0] > 0
            ):
                AddBytesToSignature(
                    signature, current_address, operand_offset[0], False
                )
                AddBytesToSignature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    AddBytesToSignature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                AddBytesToSignature(
                    signature, current_address, current_instruction_length, False
                )

            current_sig = BuildIDASignatureString(signature)
            if self.IsSignatureUnique(current_sig):
                TrimSignature(signature)
                return signature

            current_address += current_instruction_length

            if (
                not continue_outside_of_function
                and current_function
                and idaapi.get_func(current_address) != current_function
            ):
                raise Unexpected("Signature left function scope")

        raise Unexpected("Unknown")

    def GenerateSignatureForEARange(self, ea_start, ea_end, wildcard_operands):
        if ea_start == idaapi.BADADDR or ea_end == idaapi.BADADDR:
            raise Unexpected("Invalid address")

        signature = []
        sig_part_length = 0

        if not idaapi.is_code(ida_bytes.get_flags(ea_start)):
            AddBytesToSignature(signature, ea_start, ea_end - ea_start, False)
            return signature

        current_address = ea_start
        while True:
            if idaapi.user_cancelled():
                raise Unexpected("Aborted")

            instruction = idaapi.insn_t()
            current_instruction_length = idaapi.decode_insn(
                instruction, current_address
            )
            if current_instruction_length <= 0:
                if not signature:
                    raise Unexpected("Failed to decode first instruction")

                idc.msg(
                    f"Signature reached end of executable code @ {current_address:X}\n"
                )
                if current_address < ea_end:
                    AddBytesToSignature(
                        signature, current_address, ea_end - current_address, False
                    )
                TrimSignature(signature)
                return signature

            sig_part_length += current_instruction_length

            operand_offset = [0]
            operand_length = [0]
            if (
                wildcard_operands
                and self.GetOperand(instruction, operand_offset, operand_length)
                and operand_length[0] > 0
            ):
                AddBytesToSignature(
                    signature, current_address, operand_offset[0], False
                )
                AddBytesToSignature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    AddBytesToSignature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                AddBytesToSignature(
                    signature, current_address, current_instruction_length, False
                )

            current_address += current_instruction_length

            if current_address >= ea_end:
                TrimSignature(signature)
                return signature

        raise Unexpected("Unknown")

    def PrintSignatureForEA(self, signature, ea, sig_type):
        if not signature:
            idc.msg(f"Error: {signature()}\n")
            return
        signature_str = FormatSignature(signature, sig_type)
        idc.msg(f"Signature for {ea:X}: {signature_str}\n")
        if not SetClipboardText(signature_str):
            idc.msg("Failed to copy to clipboard!")

    def FindXRefs(
        self,
        ea,
        wildcard_operands,
        continue_outside_of_function,
        xref_signatures,
        max_signature_length,
    ):
        xref = idaapi.xrefblk_t()

        xref_count = 0
        for xref_ok in iter(lambda: xref.first_to(ea, idaapi.XREF_FAR), False):
            if not idaapi.is_code(ida_bytes.get_flags(xref.frm)):
                continue
            xref_count += 1

        shortest_signature_length = max_signature_length + 1

        for i, xref_ok in enumerate(
            iter(lambda: xref.first_to(ea, idaapi.XREF_FAR), False)
        ):
            if idaapi.user_cancelled():
                break

            if not idaapi.is_code(ida_bytes.get_flags(xref.frm)):
                continue

            idaapi.replace_wait_box(
                f"Processing xref {i + 1} of {xref_count} ({(i / xref_count) * 100.0:.1f}%)...\n\nSuitable Signatures: {len(xref_signatures)}\nShortest Signature: {shortest_signature_length if shortest_signature_length <= max_signature_length else 0} Bytes"
            )

            signature = self.GenerateUniqueSignatureForEA(
                xref.frm,
                wildcard_operands,
                continue_outside_of_function,
                max_signature_length,
                False,
            )
            if not signature:
                continue

            if len(signature) < shortest_signature_length:
                shortest_signature_length = len(signature)

            xref_signatures.append((xref.frm, signature))

            xref_signatures.sort(key=lambda x: len(x[1]))

    def PrintXRefSignaturesForEA(self, ea, xref_signatures, sig_type, top_count):
        if not xref_signatures:
            idc.msg("No XREFs have been found for your address\n")
            return

        top_length = min(top_count, len(xref_signatures))
        idc.msg(
            f"Top {top_length} Signatures out of {len(xref_signatures)} xrefs for {ea:X}:\n"
        )
        for i in range(top_length):
            origin_address, signature = xref_signatures[i]
            signature_str = FormatSignature(signature, sig_type)
            idc.msg(f"XREF Signature #{i + 1} @ {origin_address:X}: {signature_str}\n")

            if i == 0:
                SetClipboardText(signature_str)

    def PrintSelectedCode(self, start, end, sig_type, wildcard_operands):
        selection_size = end - start
        assert selection_size > 0

        signature = self.GenerateSignatureForEARange(start, end, wildcard_operands)
        if not signature:
            idc.msg(f"Error: {signature}\n")
            return

        signature_str = FormatSignature(signature, sig_type)
        idc.msg(f"Code for {start:X}-{end:X}: {signature_str}\n")
        SetClipboardText(signature_str)

    def SearchSignatureString(self, input):
        converted_signature_string = ""
        string_mask = ""

        match = re.search(r"x[x?]+", input)
        if match:
            string_mask = match.group(0)
        else:
            match = re.search(r"0b[0,1]+", input)
            if match:
                bits = match.group(0)[2:]
                reversed_bits = bits[::-1]
                string_mask = "".join("x" if b == "1" else "?" for b in reversed_bits)

        if string_mask:
            raw_byte_strings = []
            if GetRegexMatches(input, SIGNATURE_REGEX, raw_byte_strings) and len(
                raw_byte_strings
            ) == len(string_mask):
                converted_signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = BuildIDASignatureString(
                    converted_signature
                )
            elif GetRegexMatches(
                input, SIGNATURE_REGEX_2, raw_byte_strings
            ) and len(raw_byte_strings) == len(string_mask):
                converted_signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = BuildIDASignatureString(
                    converted_signature
                )
            else:
                idc.msg(
                    f'Detected mask "{string_mask}" but failed to match corresponding bytes\n'
                )
        else:
            input = re.sub(r"[)(\[\]]+", "", input)
            input = re.sub(r"^\s+", "", input)
            input = re.sub(r"[? ]+$", "", input) + " "
            input = re.sub(r"\\?\\x", "", input)  # Simplify hex pattern matching
            input = re.sub(r"\s+", " ", input)  # Normalize spaces
            converted_signature_string = input

        if not converted_signature_string:
            idc.msg("Unrecognized signature type\n")
            return

        idc.msg(f"Signature: {converted_signature_string}\n")
        signature_matches = self.FindSignatureOccurences(converted_signature_string)
        if not signature_matches:
            idc.msg("Signature does not match!\n")
            return
        for ea in signature_matches:
            idc.msg(f"Match @ {ea:X}\n")


# Register the plugin
def PLUGIN_ENTRY():
    return PySigMaker()

PySigMaker().run(None)
# form = SignatureMakerForm()
# form.Compile()

# # Execute the form and get results
# ok = form.Execute()

# form.Free()
