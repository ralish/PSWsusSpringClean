Changelog
=========

v0.6.1
------

- Ensure `ValidateScript()` functions return `$true` on success

v0.6.0
------

- Add `Write-Progress` support & remove most `Write-Host` calls

v0.5.0
------

- Added `-UpdateServer` parameter to support remote servers
- Ensure `Microsoft.UpdateServices.BaseApi` assembly is loaded
- Apply code formatting

v0.4.6
------

- Syntax fixes for older PowerShell versions
- Performance optimisations around array use

v0.4.5
------

- Remove unneeded files from published package
- Minor documentation updates & miscellaneous fixes

v0.4.4
------

- Added new `DeclineWindowsNextUpdates` parameter
- Added & removed various updates to local catalogue

v0.4.3
------

- Added 33 updates to the CSV

v0.4.2
------

- Enabled Strict Mode set to version 2.0 (latest at time of writing)
- Add PSScriptAnalyzer linting configuration

v0.4.1
------

- Major bug fix in retrieval of selected architecture(s) metadata

v0.4.0
------

- Added new `DeclineArchitectures` parameter & removed `DeclineItaniumUpdates`
- Added new `DeclineLanguagesExclude` & `DeclineLanguagesInclude` parameters
- Removed 3,597(!) updates from the CSV as now handled by RegEx matching
- Major performance improvements, minor fixes & documentation updates

v0.3.1
------

- Added 427 updates to the CSV (language updates)

v0.3.0
------

- Added new `RunCommonTasks` parameter
- Renamed `DeclineSecurityOnlyQualityUpdates` to `DeclineSecurityOnlyUpdates`
- Removed superfluous `DeclineUnneededUpdates` parameter
- Switch to using RegEx patterns to locate pre-release updates
- Tweaks to existing RegEx patterns & other minor changes

v0.2.0
------

- Added new `DeclinePrereleaseUpdates` parameter
- Added new `DeclineSecurityOnlyQualityUpdates` parameter
- Added 441 updates to the CSV (almost entirely language packs)
- Added new attribute in catalogue to denote pre-release updates
- Major clean-up of the code & substantial performance improvements

v0.1.2
------

- Added 2,171(!) updates to the CSV (almost entirely language packs)

v0.1.1
------

- Added 449 updates to the CSV (almost entirely language packs)
- Fixed links to license & changelog in the module manifest

v0.1
----

- Initial stable release
