#include <windows.h>

int ekranTemizleme(void)
{
    HANDLE hStdout;
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
    COORD destinationPoint;
    SMALL_RECT sourceArea;
    CHAR_INFO Fill;

    // Get console handle
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    // Retrieve console information
    if (GetConsoleScreenBufferInfo(hStdout, &csbiInfo))
    {
        // Select all the console buffer as source
        sourceArea.Top = 0;
        sourceArea.Left = 0;
        sourceArea.Bottom = csbiInfo.dwSize.Y - 1;
        sourceArea.Right = csbiInfo.dwSize.X - 1;

        // Select a place out of the console to move the buffer
        destinationPoint.X = 0;
        destinationPoint.Y = 0 - csbiInfo.dwSize.Y;

        // Configure fill character and attributes
        Fill.Char.AsciiChar = ' ';
        Fill.Attributes = csbiInfo.wAttributes;

        // Move all the information out of the console buffer and init the buffer
        ScrollConsoleScreenBuffer(hStdout, &sourceArea, NULL, destinationPoint, &Fill);

        // Position the cursor
        destinationPoint.X = 0;
        destinationPoint.Y = 0;
        SetConsoleCursorPosition(hStdout, destinationPoint);
    }

    return 0;
}