from pathlib import Path

from gui.app import derive_decryption_output_path


def test_derive_decryption_output_path_keeps_original_extension():
    output_path = derive_decryption_output_path(Path("test_files") / "sample_video.mp4")

    assert output_path == Path("outputs") / "decrypted_sample_video.mp4"


def test_derive_decryption_output_path_uses_custom_output_directory():
    output_path = derive_decryption_output_path("plain/image.png", output_dir="demo_outputs")

    assert output_path == Path("demo_outputs") / "decrypted_image.png"
