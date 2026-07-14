#include "wild_rift_menu.h"

#include "imgui.h"

void RenderWildRiftMenu(WildRiftMenuState& state) {
    if (!state.show_menu) {
        return;
    }

    ImGui::SetNextWindowSize(ImVec2(420.0f, 0.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Wild Rift", &state.show_menu)) {
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("wild_rift_tabs")) {
        if (ImGui::BeginTabItem("Display")) {
            ImGui::Checkbox("Show FPS", &state.show_fps);
            ImGui::Checkbox("FPS limiter", &state.limit_fps);
            ImGui::BeginDisabled(!state.limit_fps);
            ImGui::SliderInt("Max FPS", &state.max_fps, 30, 240);
            ImGui::EndDisabled();
            ImGui::SliderFloat("UI scale", &state.ui_scale, 0.8f, 1.4f, "%.2fx");
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Audio")) {
            ImGui::SliderFloat("Master volume", &state.master_volume, 0.0f, 1.0f, "%.0f%%");
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}
