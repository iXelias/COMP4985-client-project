#include "../include/ncurses_gui.h"

#define INPUT_HEIGHT 3
#define USER_BOX_WIDTH 15

void init_gui(GuiData *gui_data)
{
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);

    // Create windows
    gui_data->chat_win  = newwin(LINES - INPUT_HEIGHT, COLS - USER_BOX_WIDTH, 0, 0);
    gui_data->user_win  = newwin(LINES - INPUT_HEIGHT, USER_BOX_WIDTH, 0, COLS - USER_BOX_WIDTH);
    gui_data->input_win = newwin(INPUT_HEIGHT, COLS, LINES - INPUT_HEIGHT, 0);

    // Enable scrolling for the chat window
    scrollok(gui_data->chat_win, TRUE);

    // Draw boxes around the windows
    box(gui_data->chat_win, 0, 0);
    box(gui_data->user_win, 0, 0);
    box(gui_data->input_win, 0, 0);

    // Add the ">" prompt to the input window
    mvwprintw(gui_data->input_win, 1, 1, "> ");    // Print ">" at position (1, 1)

    // Move the cursor to the input window and refresh it
    wmove(gui_data->input_win, 1, 3);
    wrefresh(gui_data->input_win);

    // Refresh all windows
    wrefresh(gui_data->chat_win);
    wrefresh(gui_data->user_win);
    wrefresh(gui_data->input_win);

    // Initialize mutex for thread safety
    pthread_mutex_init(&gui_data->lock, NULL);
}

void cleanup_gui(GuiData *gui_data)
{
    // Clean up
    delwin(gui_data->chat_win);
    delwin(gui_data->user_win);
    delwin(gui_data->input_win);
    endwin();
    pthread_mutex_destroy(&gui_data->lock);
}

void add_message_to_chat(GuiData *gui_data, const char *message)
{
    pthread_mutex_lock(&gui_data->lock);
    wprintw(gui_data->chat_win, " %s\n", message);    // Append the message
    box(gui_data->chat_win, 0, 0);                    // Redraw the box
    wrefresh(gui_data->chat_win);                     // Refresh the window to show the new message
    wmove(gui_data->input_win, 1, 3);
    wrefresh(gui_data->input_win);    // Make sure cursor is in input window
    pthread_mutex_unlock(&gui_data->lock);
}

void get_user_input(GuiData *gui_data, char *input_buffer, const int buffer_size)
{
    pthread_mutex_lock(&gui_data->lock);

    // Clear only the input line
    wmove(gui_data->input_win, 1, 1);    // Move to the start of the input line
    wclrtoeol(gui_data->input_win);      // Clear the line from the cursor to the end

    // Redraw the ">" prompt
    mvwprintw(gui_data->input_win, 1, 1, "> ");

    // Move the cursor to the correct position
    wmove(gui_data->input_win, 1, 3);

    // Capture what is being inputted in the window
    echo();

    // Refresh the input window
    wrefresh(gui_data->input_win);

    // Read user input
    wgetnstr(gui_data->input_win, input_buffer, buffer_size - 1);

    // Re-disable echo after reading input
    noecho();

    // Clear input box after reading input
    wmove(gui_data->input_win, 1, 1);
    wclrtoeol(gui_data->input_win);

    // Redraw the ">" prompt
    mvwprintw(gui_data->input_win, 1, 1, "> ");

    // Move the cursor to the correct position
    wmove(gui_data->input_win, 1, 3);

    // Refresh the input window
    wrefresh(gui_data->input_win);

    pthread_mutex_unlock(&gui_data->lock);
}