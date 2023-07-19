from sys import platform

CXXFLAGS_DEBUG = ['-DSK_DEBUG']
# This subtly affects the Skia ABI and leads to crashes when passing sk_sp across the library boundary.
# For more interesting defines, check out:
# https://github.com/google/skia/blob/main/include/config/SkUserConfig.h
CXXFLAGS_DEBUG += ['-DSK_TRIVIAL_ABI=[[clang::trivial_abi]]']

defines = set()
if platform == 'win32':
    defines.add('NOMINMAX')
    # Prefer UTF-8 over UTF-16. This means no "UNICODE" define.
    # https://learn.microsoft.com/en-us/windows/apps/design/globalizing/use-utf8-code-page
    # DO NOT ADD: defines.add('UNICODE')
    # <windows.h> has a side effect of defining ERROR macro.
    # Adding NOGDI prevents it from happening.
    defines.add('NOGDI')
    # MSVCRT <source_location> needs __cpp_consteval.
    # As of Clang 16 it's not defined by default.
    # If future Clangs add it, the manual definition can be removed.
    defines.add('__cpp_consteval')
    # Silence some MSCRT-specific deprecation warnings.
    defines.add('_CRT_SECURE_NO_WARNINGS')
    # No clue what it precisely does but many projects use it.
    defines.add('WIN32_LEAN_AND_MEAN')
    defines.add('VK_USE_PLATFORM_WIN32_KHR')
    # Set Windows version to Windows 10.
    defines.add('_WIN32_WINNT=0x0A00')
    defines.add('WINVER=0x0A00')
elif platform == 'linux':
    defines.add('VK_USE_PLATFORM_XCB_KHR')

defines.add('SK_GANESH')
defines.add('SK_VULKAN')
defines.add('SK_USE_VMA')
defines.add('SK_SHAPER_HARFBUZZ_AVAILABLE')
