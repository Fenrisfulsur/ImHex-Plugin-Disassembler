#pragma once

#include <hex/plugin.hpp>
#include <hex/ui/view.hpp>
#include <hex/ui/imgui_imhex_extensions.h>

#include <imgui.h>

#include <keystone/keystone.h>
#include <capstone/capstone.h>

#include <cstdio>
#include <string>
#include <vector>

using namespace hex;

namespace ui {

    enum class SelectedRegion : int {
        EntireData,
        Selection
    };

    inline void regionSelectionPicker(SelectedRegion *region, bool showHeader = true, bool firstEntry = false) {
        if (showHeader)
            ImGui::Header("Range", firstEntry);

        if (ImGui::RadioButton("Entire Data", *region == SelectedRegion::EntireData))
            *region = SelectedRegion::EntireData;

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
    EVM,

    MAX,
    MIN = ARM
};

enum Mode
{
    // Endianess
    MODE_LITTLE_ENDIAN = 0,
	MODE_BIG_ENDIAN = 1 << 31,
    // ARM
	MODE_ARM = 0,
	MODE_THUMB = 1 << 4,
	MODE_V8 = 1 << 6,
    // x86
	MODE_16 = 1 << 1,
	MODE_32 = 1 << 2,
	MODE_64 = 1 << 3,
    // MIPS
	MODE_MIPS32 = MODE_32,
	MODE_MIPS64 = MODE_64,
	MODE_MICRO = 1 << 4,
	MODE_MIPS3 = 1 << 5,
	MODE_MIPS32R6 = 1 << 6,
    // SPARC
    MODE_SPARC32 = MODE_32,
    MODE_SPARC64 = MODE_64,
	MODE_V9 = 1 << 4,
    // PowerPC
    MODE_PPC32 = MODE_32,
    MODE_PPC64 = MODE_64,
	MODE_QPX = 1 << 4
};

class Disassembler {
public:
    constexpr static cs_arch toCSArch(Architecture architecture) {
        return static_cast<cs_arch>(architecture);
    }

    constexpr static cs_mode toCSMode(int mode) {
        return static_cast<cs_mode>(mode);
    }

    static inline bool isSupported(Architecture architecture) {
        return cs_support(toCSArch(architecture));
    }

    constexpr static const char *const ArchitectureNames[] = {
        "ARM32", "ARM64", "MIPS", "x86", "PowerPC", "Sparc", "SystemZ", "Ethereum"
    };

    static inline i32 getArchitectureSupportedCount() {
        return sizeof(ArchitectureNames) / sizeof(ArchitectureNames[0]);
    }
};

class Assembler {
public:
    constexpr static ks_arch toKSArch(Architecture architecture) {
        switch (architecture) {
            case Architecture::EVM:     return KS_ARCH_EVM;
            default:
                return static_cast<ks_arch>(int(architecture) + 1);
        }
    }

    constexpr static ks_mode toKSMode(int mode) {
        switch (mode) {
            case MODE_BIG_ENDIAN:
                return KS_MODE_BIG_ENDIAN;
            case MODE_ARM:
                return KS_MODE_ARM;
            default:
                return static_cast<ks_mode>(mode);
        }
    }

    static inline bool isSupported(Architecture architecture) {
        return ks_arch_supported(toKSArch(architecture));
    }

    static inline bool canAssemble(Architecture arch, ks_mode mode) {
        // Exceptions :
        // PowerPC : Little endian - 32 bits
        if (arch == Architecture::PPC && mode == (KS_MODE_LITTLE_ENDIAN | KS_MODE_PPC32)) {
            return false;
        }
        // x86 & ARM64 : Big endian
        if ((arch == Architecture::X86 || arch == Architecture::ARM64) && mode >= KS_MODE_BIG_ENDIAN) {
            return false;
        }
        return true;
    }
};

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
    // Disassemble and assemble stuff
    
    TaskHolder m_disassemblerTask;
    TaskHolder m_assemblerTask;

    u64 m_baseAddress   = 0;
    ui::SelectedRegion m_range = ui::SelectedRegion::EntireData;
    Region m_codeRegion = { 0, 0 };

    Architecture m_architecture = Architecture::ARM;
    cs_mode m_cs_mode           = cs_mode(0);
    ks_mode m_ks_mode           = ks_mode(0);

    std::vector<Disassembly> m_disassembly;

    void disassemble();
    void assemble();

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