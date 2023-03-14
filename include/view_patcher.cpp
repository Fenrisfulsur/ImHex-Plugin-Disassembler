#pragma once

#include <hex/plugin.hpp>
#include <hex/ui/view.hpp>
// #include <ui/widgets.hpp>
#include <imgui.h>
#include <hex/ui/imgui_imhex_extensions.h>

#include <hex/helpers/disassembler.hpp>

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
            ImGui::Header("hex.builtin.common.range", firstEntry);
            // ImGui::Header("hex.builtin.common.range"_lang, firstEntry);

        // if (ImGui::RadioButton("hex.builtin.common.range.entire_data"_lang, *region == SelectedRegion::EntireData))
        if (ImGui::RadioButton("hex.builtin.common.range.entire_data", *region == SelectedRegion::EntireData))
            *region = SelectedRegion::EntireData;
        // if (ImGui::RadioButton("hex.builtin.common.range.selection"_lang, *region == SelectedRegion::Selection))
        if (ImGui::RadioButton("hex.builtin.common.range.selection", *region == SelectedRegion::Selection))
            *region = SelectedRegion::Selection;
    }
}

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

    bool isCursorInTextViewer(ImVec2 pos, ImVec2 size);

    TextEditor m_instrEditor;
    bool m_instrEditorIsVisible = false;
};