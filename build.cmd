@ECHO OFF

for /f %%i in ('lib\lprun.exe build\BuildNugetProject.linq') do set RESULT=%%i
nuget pack %RESULT%\Rock.EmbeddedNativeLibrary.nuspec -OutputDirectory %RESULT%