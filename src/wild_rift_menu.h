#pragma once

struct WildRiftMenuState {
    bool show_menu = true;
    bool show_fps = true;
    bool limit_fps = false;
    int max_fps = 120;
    float ui_scale = 1.0f;
    float master_volume = 0.7f;
};

void RenderWildRiftMenu(WildRiftMenuState& state);
