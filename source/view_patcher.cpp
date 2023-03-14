#include <hex/plugin.hpp>

#include <hex/api/content_registry.hpp>
#include <hex/ui/view.hpp>
#include <TextEditor.h>
#include "patcher.hpp"

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

        cs_mode mode = this->m_mode;

        if (cs_open(Disassembler::toCapstoneArchitecture(this->m_architecture), mode, &capstoneHandle) == CS_ERR_OK) {

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

            // Write disassembly result in TextEditor

            std::string content = "";
            for (u32 i = 0; i < this->m_disassembly.size(); i++) {
                content += this->m_disassembly[i].mnemonic + " " + this->m_disassembly[i].operators + "\n";
            }
            this->m_textViewer.SetReadOnly(true);
            this->m_textViewer.SetShowWhitespaces(false);
            this->m_textViewer.SetText(content);

            cs_close(&capstoneHandle);
        }
    });
}

// ViewPatcher::isCursorInTextViewer() : return true if mouse is inside the text viewer
bool ViewPatcher::isCursorInTextViewer(ImVec2 pos, ImVec2 size) {
    ImVec2 mousePos  = ImGui::GetMousePos();
    // Compute absolute position of text viewer
    ImVec2 textViewerAbsPos = ImGui::GetWindowPos() + pos;

    return (mousePos.x >= textViewerAbsPos.x && mousePos.y >= textViewerAbsPos.y)
            && (mousePos.x <= textViewerAbsPos.x + size.x && mousePos.y <= textViewerAbsPos.y + size.y);
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

            if (ImGui::Combo("hex.builtin.view.disassembler.arch"_lang, reinterpret_cast<int *>(&this->m_architecture), Disassembler::ArchitectureNames, Disassembler::getArchitectureSupportedCount()))
                this->m_mode = cs_mode(0);


            if (ImGui::BeginChild("modes", ImVec2(0, ImGui::GetTextLineHeightWithSpacing() * 6), true, ImGuiWindowFlags_AlwaysAutoResize)) {

                static int littleEndian = true;
                ImGui::RadioButton("hex.builtin.common.little_endian"_lang, &littleEndian, true);
                ImGui::SameLine();
                ImGui::RadioButton("hex.builtin.common.big_endian"_lang, &littleEndian, false);

                ImGui::NewLine();

                switch (this->m_architecture) {
                    case Architecture::ARM:
                        {
                            static int mode = CS_MODE_ARM;
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.arm"_lang, &mode, CS_MODE_ARM);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.thumb"_lang, &mode, CS_MODE_THUMB);

                            static int extraMode = 0;
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.default"_lang, &extraMode, 0);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.cortex_m"_lang, &extraMode, CS_MODE_MCLASS);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.arm.armv8"_lang, &extraMode, CS_MODE_V8);

                            this->m_mode = cs_mode(mode | extraMode);
                        }
                        break;
                    case Architecture::MIPS:
                        {
                            static int mode = CS_MODE_MIPS32;
                            ImGui::RadioButton("hex.builtin.view.disassembler.mips.mips32"_lang, &mode, CS_MODE_MIPS32);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.mips.mips64"_lang, &mode, CS_MODE_MIPS64);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.mips.mips32R6"_lang, &mode, CS_MODE_MIPS32R6);

                            ImGui::RadioButton("hex.builtin.view.disassembler.mips.mips2"_lang, &mode, CS_MODE_MIPS2);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.mips.mips3"_lang, &mode, CS_MODE_MIPS3);

                            static bool microMode;
                            ImGui::Checkbox("hex.builtin.view.disassembler.mips.micro"_lang, &microMode);

                            this->m_mode = cs_mode(mode | (microMode ? CS_MODE_MICRO : cs_mode(0)));
                        }
                        break;
                    case Architecture::X86:
                        {
                            static int mode = CS_MODE_32;
                            ImGui::RadioButton("hex.builtin.view.disassembler.16bit"_lang, &mode, CS_MODE_16);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.32bit"_lang, &mode, CS_MODE_32);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.64bit"_lang, &mode, CS_MODE_64);

                            this->m_mode = cs_mode(mode);
                        }
                        break;
                    case Architecture::PPC:
                        {
                            static int mode = CS_MODE_32;
                            ImGui::RadioButton("hex.builtin.view.disassembler.32bit"_lang, &mode, CS_MODE_32);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.64bit"_lang, &mode, CS_MODE_64);

                            static bool qpx = false;
                            ImGui::Checkbox("hex.builtin.view.disassembler.ppc.qpx"_lang, &qpx);
                            static bool spe = false;
                            ImGui::Checkbox("hex.builtin.view.disassembler.ppc.spe"_lang, &spe);
                            static bool booke = false;
                            ImGui::Checkbox("hex.builtin.view.disassembler.ppc.booke"_lang, &booke);

                            this->m_mode = cs_mode(mode | (qpx ? CS_MODE_QPX : cs_mode(0)) | (spe ? CS_MODE_SPE : cs_mode(0)) | (booke ? CS_MODE_BOOKE : cs_mode(0)));
                        }
                        break;
                    case Architecture::SPARC:
                        {
                            static bool v9Mode = false;
                            ImGui::Checkbox("hex.builtin.view.disassembler.sparc.v9"_lang, &v9Mode);

                            this->m_mode = cs_mode(v9Mode ? CS_MODE_V9 : cs_mode(0));
                        }
                        break;
                    case Architecture::RISCV:
                        {
                            static int mode = CS_MODE_RISCV32;
                            ImGui::RadioButton("hex.builtin.view.disassembler.32bit"_lang, &mode, CS_MODE_RISCV32);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.64bit"_lang, &mode, CS_MODE_RISCV64);

                            static bool compressed = false;
                            ImGui::Checkbox("hex.builtin.view.disassembler.riscv.compressed"_lang, &compressed);

                            this->m_mode = cs_mode(mode | (compressed ? CS_MODE_RISCVC : cs_mode(0)));
                        }
                        break;
                    case Architecture::M68K:
                        {
                            static int selectedMode = 0;

                            std::pair<const char *, cs_mode> modes[] = {
                                {"hex.builtin.view.disassembler.m68k.000"_lang,  CS_MODE_M68K_000},
                                { "hex.builtin.view.disassembler.m68k.010"_lang, CS_MODE_M68K_010},
                                { "hex.builtin.view.disassembler.m68k.020"_lang, CS_MODE_M68K_020},
                                { "hex.builtin.view.disassembler.m68k.030"_lang, CS_MODE_M68K_030},
                                { "hex.builtin.view.disassembler.m68k.040"_lang, CS_MODE_M68K_040},
                                { "hex.builtin.view.disassembler.m68k.060"_lang, CS_MODE_M68K_060},
                            };

                            if (ImGui::BeginCombo("hex.builtin.view.disassembler.settings.mode"_lang, modes[selectedMode].first)) {
                                for (u32 i = 0; i < IM_ARRAYSIZE(modes); i++) {
                                    if (ImGui::Selectable(modes[i].first))
                                        selectedMode = i;
                                }
                                ImGui::EndCombo();
                            }

                            this->m_mode = cs_mode(modes[selectedMode].second);
                        }
                        break;
                    case Architecture::M680X:
                        {
                            static int selectedMode = 0;

                            std::pair<const char *, cs_mode> modes[] = {
                                {"hex.builtin.view.disassembler.m680x.6301"_lang,   CS_MODE_M680X_6301 },
                                { "hex.builtin.view.disassembler.m680x.6309"_lang,  CS_MODE_M680X_6309 },
                                { "hex.builtin.view.disassembler.m680x.6800"_lang,  CS_MODE_M680X_6800 },
                                { "hex.builtin.view.disassembler.m680x.6801"_lang,  CS_MODE_M680X_6801 },
                                { "hex.builtin.view.disassembler.m680x.6805"_lang,  CS_MODE_M680X_6805 },
                                { "hex.builtin.view.disassembler.m680x.6808"_lang,  CS_MODE_M680X_6808 },
                                { "hex.builtin.view.disassembler.m680x.6809"_lang,  CS_MODE_M680X_6809 },
                                { "hex.builtin.view.disassembler.m680x.6811"_lang,  CS_MODE_M680X_6811 },
                                { "hex.builtin.view.disassembler.m680x.cpu12"_lang, CS_MODE_M680X_CPU12},
                                { "hex.builtin.view.disassembler.m680x.hcs08"_lang, CS_MODE_M680X_HCS08},
                            };

                            if (ImGui::BeginCombo("hex.builtin.view.disassembler.settings.mode"_lang, modes[selectedMode].first)) {
                                for (u32 i = 0; i < IM_ARRAYSIZE(modes); i++) {
                                    if (ImGui::Selectable(modes[i].first))
                                        selectedMode = i;
                                }
                                ImGui::EndCombo();
                            }

                            this->m_mode = cs_mode(modes[selectedMode].second);
                        }
                        break;
                    case Architecture::MOS65XX:
                        {
                            static int selectedMode = 0;

                            std::pair<const char *, cs_mode> modes[] = {
                                {"hex.builtin.view.disassembler.mos65xx.6502"_lang,           CS_MODE_MOS65XX_6502         },
                                { "hex.builtin.view.disassembler.mos65xx.65c02"_lang,         CS_MODE_MOS65XX_65C02        },
                                { "hex.builtin.view.disassembler.mos65xx.w65c02"_lang,        CS_MODE_MOS65XX_W65C02       },
                                { "hex.builtin.view.disassembler.mos65xx.65816"_lang,         CS_MODE_MOS65XX_65816        },
                                { "hex.builtin.view.disassembler.mos65xx.65816_long_m"_lang,  CS_MODE_MOS65XX_65816_LONG_M },
                                { "hex.builtin.view.disassembler.mos65xx.65816_long_x"_lang,  CS_MODE_MOS65XX_65816_LONG_X },
                                { "hex.builtin.view.disassembler.mos65xx.65816_long_mx"_lang, CS_MODE_MOS65XX_65816_LONG_MX},
                            };

                            if (ImGui::BeginCombo("hex.builtin.view.disassembler.settings.mode"_lang, modes[selectedMode].first)) {
                                for (u32 i = 0; i < IM_ARRAYSIZE(modes); i++) {
                                    if (ImGui::Selectable(modes[i].first))
                                        selectedMode = i;
                                }
                                ImGui::EndCombo();
                            }

                            this->m_mode = cs_mode(modes[selectedMode].second);
                        }
                        break;
                    case Architecture::BPF:
                        {
                            static int mode = CS_MODE_BPF_CLASSIC;
                            ImGui::RadioButton("hex.builtin.view.disassembler.bpf.classic"_lang, &mode, CS_MODE_BPF_CLASSIC);
                            ImGui::SameLine();
                            ImGui::RadioButton("hex.builtin.view.disassembler.bpf.extended"_lang, &mode, CS_MODE_BPF_EXTENDED);

                            this->m_mode = cs_mode(mode);
                        }
                        break;
                    case Architecture::EVM:
                    case Architecture::TMS320C64X:
                    case Architecture::ARM64:
                    case Architecture::SYSZ:
                    case Architecture::XCORE:
                    case Architecture::WASM:
                    case Architecture::MAX:
                        this->m_mode = cs_mode(0);
                        break;
                }
            }
            ImGui::EndChild();

            ImGui::BeginDisabled(this->m_disassemblerTask.isRunning() || this->m_instrEditorIsVisible);
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

            // Compute text viewer and editor size
            auto textViewerPos  = ImGui::GetCursorPos();
            auto textViewerSize = ImGui::GetContentRegionAvail();
            textViewerSize.x *= 0.49;  // side by side widget
            textViewerSize.y *= 3.75 / 5.0;
            //textViewerSize.y -= ImGui::GetTextLineHeightWithSpacing();
            this->m_textViewer.Render("Disassembly viewer", textViewerSize, false);

            if (this->m_instrEditorIsVisible) {
                // Use the same size as the text viewer to place it next to it
                ImGui::SameLine();
                this->m_instrEditor.SetShowWhitespaces(false);
                this->m_instrEditor.Render("Instruction editor", textViewerSize, false);
            }
            ImGui::Spacing();

            // Add undo and redo button because TextEditor is read-only
            this->m_textViewer.SetReadOnly(false);
            ImGui::BeginDisabled(!this->m_textViewer.CanUndo() || this->m_instrEditorIsVisible);
            if (ImGui::Button(" < Undo ")) {
                this->m_textViewer.Undo();
                this->m_textViewer.Undo();
            }
            ImGui::EndDisabled();

            ImGui::SameLine();

            ImGui::BeginDisabled(!this->m_textViewer.CanRedo() || this->m_instrEditorIsVisible);
            if (ImGui::Button(" Redo > ")) {
                this->m_textViewer.Redo();
                this->m_textViewer.Redo();
            }
            ImGui::EndDisabled();
            this->m_textViewer.SetReadOnly(true);

            if (this->m_instrEditorIsVisible) {
                // Add WindowPadding two times to align button with TextEditor
                ImGui::SameLine(textViewerSize.x + ImGui::GetStyle().WindowPadding.x * 2.0);
                if (ImGui::Button("Cancel")) {
                    this->m_instrEditorIsVisible = false;
                    this->m_textViewer.SetHandleMouseInputs(true);
                    this->m_textViewer.SetHandleKeyboardInputs(true);
                }
                ImGui::SameLine();
                if (ImGui::Button("Save the modifications")) {
                    this->m_instrEditorIsVisible = false;
                    this->m_textViewer.SetHandleMouseInputs(true);
                    this->m_textViewer.SetHandleKeyboardInputs(true);
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
                if (ImGui::BeginPopupContextItem("Patch menu", 2)) {
                    if (ImGui::Selectable("Patch these instructions")) {
                        // Set the text of instruction editor from selection and make it visible
                        this->m_instrEditor.SetText(this->m_textViewer.GetSelectedText().c_str());
                        this->m_instrEditorIsVisible = true;
                        // Disable mouse and keyboard event handler in the text viewer
                        this->m_textViewer.SetHandleMouseInputs(false);
                        this->m_textViewer.SetHandleKeyboardInputs(false);
                        ImGui::CloseCurrentPopup();
                    }
                    // TODO : add "replace by nop" option
                }
                ImGui::EndPopup();
            }
        }
    }
    ImGui::End();
}

IMHEX_PLUGIN_SETUP("C++ Template Plugin", "Plugin Author", "Plugin Description") {

    hex::ContentRegistry::Views::add<ViewPatcher>();

}
