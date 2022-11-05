#pragma once

struct UObject;
struct UClass;
struct UConsole;
struct UGameInstance;

struct UGameViewportClient
{
    char unknown1[0x40];
    UConsole* ViewportConsole;
	char unknown2[0x28];
	UGameInstance* GameInstance;
};

struct UEngine
{
    char unknown1[0xF8];
    UClass* ConsoleClass;
    char unknown2[0x688];
    UGameViewportClient* GameViewportClient;
};