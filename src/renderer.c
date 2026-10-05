#include "renderer.h"

#include <stdio.h>
#include <string.h>

#include <SDL2/SDL_image.h>

static void draw_text(SDL_Renderer *renderer, const char *text, int x, int y, int scale) {
    /* Minimal built-in 5x7 fallback font. It deliberately needs no downloaded font,
       so basic operation remains visible when a font or icon package is absent. */
    static const unsigned char glyphs[128][7] = {
        ['A']={0x7E,0x09,0x09,0x09,0x7E}, ['B']={0x7F,0x49,0x49,0x49,0x36},
        ['C']={0x3E,0x41,0x41,0x41,0x22}, ['D']={0x7F,0x41,0x41,0x22,0x1C},
        ['E']={0x7F,0x49,0x49,0x49,0x41}, ['F']={0x7F,0x09,0x09,0x09,0x01},
        ['G']={0x3E,0x41,0x49,0x49,0x72}, ['H']={0x7F,0x08,0x08,0x08,0x7F},
        ['I']={0x41,0x41,0x7F,0x41,0x41}, ['L']={0x7F,0x40,0x40,0x40,0x40},
        ['M']={0x7F,0x02,0x0C,0x02,0x7F}, ['N']={0x7F,0x04,0x08,0x10,0x7F},
        ['O']={0x3E,0x41,0x41,0x41,0x3E}, ['P']={0x7F,0x09,0x09,0x09,0x06},
        ['R']={0x7F,0x09,0x19,0x29,0x46}, ['S']={0x46,0x49,0x49,0x49,0x31},
        ['T']={0x01,0x01,0x7F,0x01,0x01}, ['U']={0x3F,0x40,0x40,0x40,0x3F},
        ['V']={0x1F,0x20,0x40,0x20,0x1F}, ['Y']={0x07,0x08,0x70,0x08,0x07},
        ['0']={0x3E,0x51,0x49,0x45,0x3E}, ['1']={0x00,0x42,0x7F,0x40,0x00},
        ['2']={0x42,0x61,0x51,0x49,0x46}, ['3']={0x21,0x41,0x45,0x4B,0x31},
        ['4']={0x18,0x14,0x12,0x7F,0x10}, ['5']={0x27,0x45,0x45,0x45,0x39},
        ['6']={0x3C,0x4A,0x49,0x49,0x30}, ['7']={0x01,0x71,0x09,0x05,0x03},
        ['8']={0x36,0x49,0x49,0x49,0x36}, ['9']={0x06,0x49,0x49,0x29,0x1E},
        ['-']={0x08,0x08,0x08,0x08,0x08}, [':']={0x28,0x00,0x00,0x28,0x00},
        ['/']={0x60,0x10,0x08,0x04,0x03}, ['.']={0x20,0x00,0x20,0x00,0x00},
        [' ']={0}
    };
    int cx=x;
    SDL_SetRenderDrawColor(renderer,245,247,250,255);
    for(const char *p=text;*p;++p) {
        unsigned char c=(unsigned char)*p;
        if(c=='\n'){x=cx;y+=8*scale;continue;}
        const unsigned char *g=(c<128)?glyphs[c]:glyphs[' '];
        if(g==NULL)g=glyphs[' '];
        for(int row=0;row<7;++row)for(int col=0;col<7;++col) if(g[row]&(1u<<(6-col)))
            for(int sy=0;sy<scale;++sy)for(int sx=0;sx<scale;++sx) SDL_RenderDrawPoint(renderer,x+col*scale+sx,y+row*scale+sy);
        x += 8*scale;
    }
}

bool renderer_load_background(SceneRenderer *scene, SDL_Renderer *renderer, const char *image_path) {
    if (scene == NULL || renderer == NULL) return false;
    scene->background = NULL;
    if (image_path != NULL) scene->background = IMG_LoadTexture(renderer, image_path);
    return true;
}

void renderer_draw_background(const SceneRenderer *scene, SDL_Renderer *renderer,
                              int window_width, int window_height) {
    SDL_Rect dst={0,0,window_width,window_height};
    SDL_SetRenderDrawColor(renderer,18,24,38,255);
    SDL_RenderClear(renderer);
    if (scene != NULL && scene->background != NULL) SDL_RenderCopy(renderer,scene->background,NULL,&dst);
    SDL_SetRenderDrawColor(renderer,52,64,84,230);
    SDL_Rect panel={32,32,520,220}; SDL_RenderFillRect(renderer,&panel);
    draw_text(renderer,"VISUAL WINDOW",52,56,3);
    draw_text(renderer,"BASIC OPERATIONS",52,112,2);
    draw_text(renderer,"OK    SETTINGS    ROLLBACK",52,156,2);
    draw_text(renderer,"MISSING GRAPHICS FALLBACK ACTIVE",52,204,1);
    SDL_RenderPresent(renderer);
}

void renderer_destroy(SceneRenderer *scene) {
    if (scene == NULL) return;
    if (scene->background != NULL) { SDL_DestroyTexture(scene->background); scene->background=NULL; }
}
