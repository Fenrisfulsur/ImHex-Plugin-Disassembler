#include <hex/plugin.hpp>

#include <hex/api/content_registry.hpp>
#include <hex/ui/view.hpp>
#include <hex/helpers/logger.hpp>

#include <TextEditor.h>
#include "view_patcher.hpp"

ViewPatcher::ViewPatcher() : View("Patcher") {
    EventManager::subscribe<EventProviderDeleted>(this, [this](const auto*) {
        this->m_disassembly.clear();
    });
}

ViewPatcher::~ViewPatcher() {
    EventManager::unsubscribe<EventDataChanged>(this);
    EventManager::unsubscribe<EventRegionSelected>(this);
    EventManager::unsubscribe<EventProviderDeleted>(this);
}

void ViewPatcher::disassemble() {
    this->m_disassembly.clear();

    this->m_disassemblerTask = TaskManager::createTask("hex.builtin.view.disassembler.disassembling", this->m_codeRegion.getSize(), [this](auto &task) {

        csh capstoneHandle;
        cs_insn *instructions = nullptr;

        cs_mode mode = this->m_cs_mode;

        if (cs_open(Disassembler::toCSArch(this->m_architecture), mode, &capstoneHandle) == CS_ERR_OK) {

            cs_option(capstoneHandle, CS_OPT_SKIPDATA, CS_OPT_ON);

            auto provider = ImHexApi::Provider::get();
            std::vector<u8> buffer(2048, 0x00);
            size_t size = this->m_codeRegion.getSize();

            for (u64 address = 0; address < size; address += 2048) {
                task.update(address);

                size_t bufferSize = std::min(u64(2048), (size - address));
                provider->read(this->m_codeRegion.getStartAddress() + address, buffer.data(), bufferSize);

                size_t instructionCount = cs_disasm(capstoneHandle, buffer.data(), bufferSize, this->m_baseAddress + address, 0, &instructions);
                if (instructionCount == 0)
                    break;

                this->m_disassembly.reserve(this->m_disassembly.size() + instructionCount);

                u64 usedBytes = 0;
                for (u32 i = 0; i < instructionCount; i++) {
                    const auto &instr       = instructions[i];
                    Disassembly disassembly = { };
                    disassembly.address     = instr.address;
                    disassembly.offset      = this->m_codeRegion.getStartAddress() + address + usedBytes;
                    disassembly.size        = instr.size;
                    disassembly.mnemonic    = instr.mnemonic;
                    disassembly.operators   = instr.op_str;

                    for (u16 j = 0; j < instr.size; j++)
                        disassembly.bytes += hex::format("{0:02X} ", instr.bytes[j]);
                    disassembly.bytes.pop_back();

                    this->m_disassembly.push_back(disassembly);

                    usedBytes += instr.size;
                }

                if (instructionCount < bufferSize)
                    address -= (bufferSize - usedBytes);

                cs_free(instructions, instructionCount);
            }

            cs_close(&capstoneHandle);
            this->setTextFromDisassembly();
        }
    });
}

void ViewPatcher::assemble() {

    this->m_assemblerTask = TaskManager::createTask("Assembling", this->m_codeRegion.getSize(), [this](auto &task) {
        ks_engine *ks;
        ks_mode mode = this->m_ks_mode;
        ks_arch arch = Assembler::toKSArch(this->m_architecture);

        size_t count;
        unsigned char *encode;
        size_t size;

        if (ks_open(arch, mode, &ks) == KS_ERR_OK) {

            hex::log::info("ks_open success");
            std::string code = this->m_textViewer.GetText();
            if (ks_err(ks_asm(ks, code.c_str(), 0, &encode, &size, &count)) != KS_ERR_OK) {

                hex::log::info("Error: ks_asm() failed (error = {} / count : {})", int(ks_errno(ks)), int(count));

            } else {

                size_t i;
                std::printf("%s = ", code.c_str());
                for (i = 0; i < size; i++) {
                    task.update(i);
                    std::printf("%02x ", encode[i]);
                }
                std::printf("\n");
                std::printf("Compiled: %lu bytes, statements: %lu\n", size, count);

                ks_free(encode);
            }
            ks_close(ks);

        } else {
            // exception
            hex::log::info("Error: ks_open() failed (error = {})", int(ks_errno(ks)));
        }
    });
}

void ViewPatcher::setTextFromDisassembly() {
    std::string content = "";
    for (u32 i = 0; i < this->m_disassembly.size(); i++) {
        content += this->m_disassembly[i].mnemonic + " " + this->m_disassembly[i].operators + "\n";
    }
    this->m_textViewer.SetReadOnly(true);
    this->m_textViewer.SetShowWhitespaces(false);
    this->m_textViewer.SetText(content);
}

// ViewPatcher::isCursorInTextViewer() : return true if mouse is inside the text viewer
bool ViewPatcher::isCursorInTextViewer(ImVec2 pos, ImVec2 size) {
    ImVec2 mousePos  = ImGui::GetMousePos();
    // Compute absolute position of text viewer
    ImVec2 textViewerAbsPos = ImGui::GetWindowPos() + pos;

    return (mousePos.x >= textViewerAbsPos.x && mousePos.y >= textViewerAbsPos.y)
            && (mousePos.x <= textViewerAbsPos.x + size.x && mousePos.y <= textViewerAbsPos.y + size.y);
}

// Make the instruction editor visible and disable handling of mouse and keyboard inputs for text viewer
void ViewPatcher::setInstrEditorVisible(bool isVisible) {
    this->m_instrEditorIsVisible = isVisible;
    this->m_textViewer.SetHandleMouseInputs(!isVisible);
    this->m_textViewer.SetHandleKeyboardInputs(!isVisible);
}

void ViewPatcher::drawContent() {

    if (ImGui::Begin(View::toWindowName("Patcher").c_str(), &this->getWindowOpenState(), ImGuiWindowFlags_NoCollapse)) {

        auto provider = ImHexApi::Provider::get();
        if (ImHexApi::Provider::isValid() && provider->isReadable()) {
            ImGui::TextUnformatted("hex.builtin.view.disassembler.position"_lang);
            ImGui::Separator();

            ImGui::InputHexadecimal("hex.builtin.view.disassembler.base"_lang, &this->m_baseAddress, ImGuiInputTextFlags_CharsHexadecimal);

            ui::regionSelectionPicker(&this->m_range);
            switch (this->m_range) {
                case ui::SelectedRegion::Selection: {
                    auto region = ImHexApi::HexEditor::getSelection();
                    if (region.has_value()) {
                        this->m_codeRegion = region.value();
                    }
                }
                    break;
                case ui::SelectedRegion::EntireData: {
                    auto base = provider->getBaseAddress();
                    this->m_codeRegion = { base, base + provider->getActualSize() - 1 };
                }
                break;
            }

            if (ImGui::IsItemEdited()) {
                // Force execution of Region Selection Event
                ImHexApi::HexEditor::setSelection(0, 0);
            }

            ImGui::NewLine();
            ImGui::TextUnformatted("hex.builtin.view.disassembler.settings.header"_lang);
            ImGui::Separator();

            if (ImGui::Combo("hex.builtin.view.disassembler.arch"_lang, reinterpret_cast<int *>(&this->m_architecture), Disassembler::ArchitectureNames, Disassembler::getArchitectureSupportedCount())) {
                this->m_cs_mode = cs_mode(0);
                this->m_ks_mode = ks_mode(0);
            }

            if (ImGui::BeginChild("modes", ImVec2(0, ImGui::GetTextLineHeightWithSpacing() * 6), true, ImGuiWindowFlags_AlwaysAutoResize)) {

                static int littleEndian = true;
                ImGui::RadioButton("hex.builtin.common.little_endian"_lang, &littleEndian, true);
                ImGui::SameLine();
                ImGui::RadioButton("hex.builtin.common.big_endian"_lang, &littleEndian, false);

                ImGui::NewLine();

                switch (this->m_architecture) {
                    case Architecture::ARM:
                        {
                            static int mode = MODE_ARM;
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.arm"_lang, &mode, MODE_ARM);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.thumb"_lang, &mode, MODE_THUMB);

                            static int extraMode = 0;
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.default"_lang, &extraMode, 0);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.armv8"_lang, &extraMode, MODE_V8);

                            this->m_cs_mode = cs_mode(Disassembler::toCSMode(mode) | Disassembler::toCSMode(extraMode));
                            this->m_ks_mode = ks_mode(Assembler::toKSMode(mode) | (extraMode == 0 ? ks_mode(0) : Assembler::toKSMode(extraMode)));
                        }
                        break;
                    case Architecture::MIPS:
                        {
                            static int mode = MODE_MIPS32;
                            ImGui::RadioButton("hex.builtin.view.disassembler.mips.mips32"_lang, &mode, MODE_MIPS32);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.mips.mips64"_lang, &mode, MODE_MIPS64);

                            this->m_cs_mode = cs_mode(Disassembler::toCSMode(mode));
                            this->m_ks_mode = ks_mode(Assembler::toKSMode(mode));
                        }
                        break;
                    case Architecture::X86:
                        {
                            static int mode = MODE_32;
                            ImGui::RadioButton("hex.builtin.view.disassembler.16bit"_lang, &mode, MODE_16);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.32bit"_lang, &mode, MODE_32);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.64bit"_lang, &mode, MODE_64);

                            this->m_cs_mode = Disassembler::toCSMode(mode);
                            this->m_ks_mode = Assembler::toKSMode(mode);
                        }
                        break;
                    case Architecture::PPC:
                        {
                            static int mode = MODE_32;
                            ImGui::RadioButton("hex.builtin.view.disassembler.32bit"_lang, &mode, MODE_32);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.64bit"_lang, &mode, MODE_64);

                            this->m_cs_mode = cs_mode(Disassembler::toCSMode(mode));
                            this->m_ks_mode = ks_mode(Assembler::toKSMode(mode));
                        }
                        break;
                    case Architecture::SPARC:
                        {
                            this->m_cs_mode = cs_mode(0);
                            this->m_ks_mode = KS_MODE_SPARC32;
                        }
                        break;
                    case Architecture::EVM:
                    case Architecture::ARM64:
                    case Architecture::SYSZ:
                    case Architecture::MAX:
                        this->m_cs_mode = cs_mode(0);
                        this->m_ks_mode = ks_mode(0);
                        break;
                }

                // add big endian offset
                if (!littleEndian) {
                    this->m_cs_mode = cs_mode(this->m_cs_mode | CS_MODE_BIG_ENDIAN);
                    this->m_ks_mode = ks_mode(this->m_ks_mode | KS_MODE_BIG_ENDIAN);
                }
            }
            ImGui::EndChild();


            ImGui::BeginDisabled(this->m_instrEditorIsVisible || this->m_disassemblerTask.isRunning());
            {
                if (ImGui::Button("hex.builtin.view.disassembler.disassemble"_lang))
                    this->disassemble();
            }
            ImGui::EndDisabled();

            if (this->m_disassemblerTask.isRunning()) {
                ImGui::SameLine();
                ImGui::TextSpinner("hex.builtin.view.disassembler.disassembling"_lang);
            }

            ImGui::NewLine();

            ImGui::TextUnformatted("hex.builtin.view.disassembler.disassembly.title"_lang);
            ImGui::Separator();

            // Text viewer and editor render and events handling

            // Write disassembly result in TextEditor
            if (!this->m_disassemblerTask.isRunning()) {

                // Compute text viewer and editor size
                auto textViewerPos  = ImGui::GetCursorPos();
                auto textViewerSize = ImGui::GetContentRegionAvail();
                textViewerSize.x *= 0.49;  // side by side widget
                textViewerSize.y *= 4.5 / 5.0;
                this->m_textViewer.SetImGuiChildIgnored(true);
                if (ImGui::BeginChild("Disassembly viewer", textViewerSize, true, ImGuiWindowFlags_NoNavInputs)) {
                    this->m_textViewer.Render("Disassembly viewer", textViewerSize, true);
                }
                ImGui::EndChild();
                

                if (this->m_instrEditorIsVisible) {
                    // Use the same size as the text viewer to place it next to it
                    ImGui::SameLine();
                    this->m_instrEditor.SetShowWhitespaces(false);
                    this->m_instrEditor.SetImGuiChildIgnored(true);
                    if (ImGui::BeginChild("Instruction editor", textViewerSize, true, ImGuiWindowFlags_NoNavInputs)) {
                        this->m_instrEditor.Render("Instruction editor", textViewerSize, true);
                    }
                    ImGui::EndChild();
                }
                ImGui::Spacing();

                // Add undo and redo button because TextEditor is read-only
                this->m_textViewer.SetReadOnly(false);  // disable read-only to undo/redo modifications
                ImGui::BeginDisabled(!this->m_textViewer.CanUndo() || this->m_instrEditorIsVisible);
                {
                    if (ImGui::Button(" < Undo ")) {
                        this->m_textViewer.Undo();  // undo Paste()
                        this->m_textViewer.Undo();  // undo Delete()
                    }
                }
                ImGui::EndDisabled();

                ImGui::SameLine();

                ImGui::BeginDisabled(!this->m_textViewer.CanRedo() || this->m_instrEditorIsVisible);
                {
                    if (ImGui::Button(" Redo > ")) {
                        this->m_textViewer.Redo();  // redo Delete()
                        this->m_textViewer.Redo();  // redo Paste()
                    }
                }
                ImGui::EndDisabled();
                this->m_textViewer.SetReadOnly(true);   // re-enable read-only

                ImGui::SameLine(textViewerSize.x - ImGui::CalcTextSize("Assemble").x);

                // Assemble button is disabled for each mode not supported by Keystone
                ImGui::BeginDisabled(!Assembler::canAssemble(this->m_architecture, this->m_ks_mode) || this->m_assemblerTask.isRunning());
                {
                    if (ImGui::Button("Assemble")) {
                        this->assemble();
                    }
                }
                ImGui::EndDisabled();

                if (this->m_instrEditorIsVisible) {
                    // Add WindowPadding two times to align button with TextEditor
                    ImGui::SameLine(textViewerSize.x + ImGui::GetStyle().WindowPadding.x * 2.0);
                    if (ImGui::Button("Cancel")) {
                        setInstrEditorVisible(false);
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Save the modifications")) {
                        setInstrEditorVisible(false);
                        this->m_textViewer.SetReadOnly(false);
                        // Cut the selection and replace it by the modified instructions
                        this->m_textViewer.Delete();
                        // Get the text and remove last character (\n)
                        std::string modifiedInstr = this->m_instrEditor.GetText();
                        modifiedInstr.pop_back();
                        ImGui::SetClipboardText(modifiedInstr.c_str());
                        this->m_textViewer.Paste();
                        this->m_textViewer.SetReadOnly(true);
                    }
                }

                if (this->isCursorInTextViewer(textViewerPos, textViewerSize) && !this->m_instrEditorIsVisible) {
                    ImGuiIO& io = ImGui::GetIO();
                    auto ctrl = io.ConfigMacOSXBehaviors ? io.KeySuper : io.KeyCtrl;

                    // If cursor position change and there isn't already a selection, reset the selection
                    if (this->m_textViewer.IsCursorPositionChanged() && !this->m_textViewer.HasSelection() && !ImGui::IsPopupOpen("Patch menu")) {
                        this->m_viewerHasSelection = false;
                        this->m_viewerSelectionStart = this->m_textViewer.GetCursorPosition();
                    }

                    // Set selection on Ctrl+A
                    if (ctrl && ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_A))) {
                        this->m_viewerHasSelection = true;
                    }

                    // Change selection mode to lines when the user finish his selection (on mouse/shift key released)
                    if (this->m_textViewer.HasSelection()
                            && (ImGui::IsMouseReleased(ImGuiMouseButton_Left) || ImGui::IsKeyReleased(ImGuiKey_LeftShift) || ImGui::IsKeyReleased(ImGuiKey_RightShift))
                            && !ImGui::IsPopupOpen("Patch menu")) {
                        this->m_viewerSelectionEnd = this->m_textViewer.GetCursorPosition();
                        this->m_textViewer.SetSelection(this->m_viewerSelectionStart, this->m_viewerSelectionEnd, TextEditor::SelectionMode::Line);
                        this->m_viewerHasSelection = true;
                    }
                    
                    // Open the popup menu on right click
                    if (ImGui::IsMouseClicked(ImGuiMouseButton_Right) && this->m_viewerHasSelection) {
                        ImGui::OpenPopup("Patch menu");
                    }

                    // Popup menu for patching instruction
                    if (ImGui::BeginPopupContextItem("Patch menu", 3)) {
                        if (ImGui::Selectable("Patch these instructions")) {
                            // Set the text of instruction editor from selection and make it visible
                            this->m_instrEditor.SetText(this->m_textViewer.GetSelectedText().c_str());
                            setInstrEditorVisible(true);
                            //ImGui::CloseCurrentPopup();
                        }
                        // TODO : add "replace by nop" option
                        if (ImGui::Selectable("Replace by NOP")) {
                            // Replace instructions selected by nop
                            std::printf("Replace by NOP\n");
                        }
                    }
                    ImGui::EndPopup();
                }
            }
        }
    }
    ImGui::End();
}

IMHEX_PLUGIN_SETUP("C++ Template Plugin", "Plugin Author", "Plugin Description") {

    hex::ContentRegistry::Views::add<ViewPatcher>();

}
