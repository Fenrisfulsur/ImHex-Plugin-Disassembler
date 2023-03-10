#pragma once

#include <hex/plugin.hpp>
#include <hex/ui/view.hpp>
// #include <ui/widgets.hpp>
#include <imgui.h>
#include <hex/ui/imgui_imhex_extensions.h>

#include <keystone/keystone.h>
#include <capstone/capstone.h>

#include <cstdio>
#include <string>
#include <vector>

namespace ui {

    enum class SelectedRegion : int {
        EntireData,
        Selection
    };

    inline void regionSelectionPicker(SelectedRegion *region, bool showHeader = true, bool firstEntry = false) {
        if (showHeader)
            ImGui::Header("Range", firstEntry);
            // ImGui::Header("hex.builtin.common.range"_lang, firstEntry);

        // if (ImGui::RadioButton("hex.builtin.common.range.entire_data"_lang, *region == SelectedRegion::EntireData))
        if (ImGui::RadioButton("Entire Data", *region == SelectedRegion::EntireData))
            *region = SelectedRegion::EntireData;
        // if (ImGui::RadioButton("hex.builtin.common.range.selection"_lang, *region == SelectedRegion::Selection))
        if (ImGui::RadioButton("Selection", *region == SelectedRegion::Selection))
            *region = SelectedRegion::Selection;
    }
}

enum class Architecture : i32
{
    ARM,
    ARM64,
    MIPS,
    X86,
    PPC,
    SPARC,
    SYSZ,
    XCORE,
    M68K,
    TMS320C64X,
    M680X,
    EVM,
    MOS65XX,
    WASM,
    BPF,
    RISCV,

    MAX,
    MIN = ARM
};

class Disassembler {
public:
    constexpr static cs_arch toCapstoneArchitecture(Architecture architecture) {
        return static_cast<cs_arch>(architecture);
    }

    static inline bool isSupported(Architecture architecture) {
        return cs_support(toCapstoneArchitecture(architecture));
    }

    constexpr static const char *const ArchitectureNames[] = { "ARM32", "ARM64", "MIPS", "x86", "PowerPC", "Sparc", "SystemZ", "XCore", "68K", "TMS320C64x", "680X", "Ethereum", "MOS65XX", "WebAssembly", "Berkeley Packet Filter", "RISC-V" };

    static inline i32 getArchitectureSupportedCount() {
        static i32 supportedCount = -1;

        if (supportedCount != -1) {
            return supportedCount;
        }

        for (supportedCount = static_cast<i32>(Architecture::MIN); supportedCount < static_cast<i32>(Architecture::MAX); supportedCount++) {
            if (!cs_support(supportedCount)) {
                break;
            }
        }

        return supportedCount;
    }
};

using namespace hex;

struct Disassembly {
    u64 address;
    u64 offset;
    size_t size;
    std::string bytes;
    std::string mnemonic;
    std::string operators;
};

class ViewPatcher : public View {
public:
    explicit ViewPatcher();
    ~ViewPatcher() override;

    void drawContent() override;

private:
    // Disassembly stuff
    
    TaskHolder m_disassemblerTask;

    u64 m_baseAddress   = 0;
    ui::SelectedRegion m_range = ui::SelectedRegion::EntireData;
    Region m_codeRegion = { 0, 0 };

    Architecture m_architecture = Architecture::ARM;
    cs_mode m_mode              = cs_mode(0);

    std::vector<Disassembly> m_disassembly;

    void disassemble();

    // Instructions viewer and editor

    TextEditor m_textViewer;
    TextEditor::Coordinates m_viewerSelectionStart;
    TextEditor::Coordinates m_viewerSelectionEnd;
    bool m_viewerHasSelection = false;

    void setTextFromDisassembly();
    bool isCursorInTextViewer(ImVec2 pos, ImVec2 size);
    void setInstrEditorVisible(bool isVisible);

    TextEditor m_instrEditor;
    bool m_instrEditorIsVisible = false;
};
