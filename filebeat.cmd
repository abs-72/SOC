@echo off
set args=%*

if "%args%" == "" (
    set args=--help
)

set beat_bin=%~dp0%~n0
set beat_data=%beat_bin%

"%beat_bin%\%~n0.exe" ^
    --path.home "%beat_bin%" ^
    --path.config "%beat_data%" ^
    --path.data "%beat_data%\data" ^
    --path.logs "%beat_data%\logs" ^
    --E logging.files.redirect_stderr=true ^
    %args%