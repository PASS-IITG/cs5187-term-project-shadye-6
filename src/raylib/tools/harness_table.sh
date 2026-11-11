# Sourced by run scripts. name | dict | max_len | timeout(s) | weight (relative CPU share)
# Weights encode attack-surface priority: hand-written raylib parsers and multi-stage loaders
# (gltf/obj/iqm/m3d/vox, rl_gputex, BDF/FNT, image VM) get more CPU than mature stb/dr_* decoders.
HARNESSES="
fuzz_model_gltf      gltf.dict          1048576 25 6
fuzz_model_glb       gltf.dict          1048576 25 4
fuzz_model_obj       obj.dict           262144  25 4
fuzz_model_iqm       misc_formats.dict  524288  25 4
fuzz_model_m3d       misc_formats.dict  524288  25 4
fuzz_model_vox       vox.dict           262144  25 3
fuzz_image_ops       -                  16384   25 6
fuzz_render_vm       -                  16384   25 5
fuzz_image_dds       misc_formats.dict  262144  10 3
fuzz_image_ktx       misc_formats.dict  262144  10 3
fuzz_image_pvr       misc_formats.dict  262144  10 3
fuzz_image_pkm       misc_formats.dict  262144  10 2
fuzz_image_astc      misc_formats.dict  262144  10 2
fuzz_image_qoi       misc_formats.dict  262144  10 2
fuzz_image_png       png.dict           524288  10 2
fuzz_image_gif       gif.dict           262144  10 2
fuzz_image_bmp       -                  262144  10 1
fuzz_image_tga       -                  262144  10 1
fuzz_image_jpg       -                  262144  10 1
fuzz_image_psd       misc_formats.dict  262144  10 1
fuzz_image_hdr       misc_formats.dict  262144  10 1
fuzz_image_pic       -                  262144  10 1
fuzz_image_pnm       -                  65536   10 1
fuzz_font_ttf        -                  1048576 25 3
fuzz_font_otf        -                  1048576 25 2
fuzz_font_bdf        bdf.dict           131072  25 3
fuzz_font_fnt        fnt.dict           262144  25 3
fuzz_audio_wav       wav.dict           262144  25 3
fuzz_audio_qoa       audio.dict         262144  25 2
fuzz_audio_xm        tracker.dict       262144  25 3
fuzz_audio_mod       tracker.dict       262144  25 3
fuzz_audio_mp3       audio.dict         262144  25 1
fuzz_audio_ogg       audio.dict         262144  25 1
fuzz_audio_flac      audio.dict         262144  25 1
fuzz_text            -                  8192    10 2
fuzz_codec           -                  65536   10 1
fuzz_automation      rae.dict           65536   10 2
"
export ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:handle_abort=1:symbolize=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:suppressions=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ubsan.supp"
