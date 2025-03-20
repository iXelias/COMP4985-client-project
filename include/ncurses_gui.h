#ifndef NCURSES_GUI_H
#define NCURSES_GUI_H

#include <ncurses.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct
{
    WINDOW         *chat_win;
    WINDOW         *input_win;
    WINDOW         *user_win;
    pthread_mutex_t lock;
} GuiData;

void init_gui(GuiData *gui_data);
void cleanup_gui(GuiData *gui_data);
void add_message_to_chat(GuiData *gui_data, const char *message);
void get_user_input(GuiData *gui_data, char *input_buffer, int buffer_size);

#endif    // NCURSES_GUI_H
