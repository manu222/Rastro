package normalise

// The provider tables as the providers declare them.
//
// Generated from the event templates of Windows 10 Pro 10.0.19045, read with
// Get-WinEvent -ListProvider (scripts/manifest-forms.ps1): one row per field of
// every event, with the outType the provider declares for it. That is the
// source the hand tables in tables.go were standing in for. win:HexInt32 and
// win:HexInt64 are FormHex; the unsigned and signed integer types are
// FormDecimal; xs:string is FormText.
//
// Only fields that are hexadecimal in at least one event are listed, because
// that is the distinction a parser can erase: a field Windows declares as
// HexInt64 that a parser hands back as an integer renders in the wrong base
// and stops every rule that mentions it. The default for a field is the form
// most of its events declare; an event that declares otherwise is an
// exception, and there are 35 of them across 33 events in the Security
// provider, ProcessId alone in fourteen. Sysmon's templates were read from
// v15.22 on the same machine: 276 fields in 30 events, of which only two are
// hexadecimal, and both were already in its hand table.
//
// The hand tables win where both speak, and TestTheHandTablesAgreeWithTheManifests
// fails the build if they ever disagree: a table that contradicts its own
// provider is a table resting on somebody's memory.

var securityManifest = manifest{
	Fields: map[string]Form{
		"AccessMask":                             FormHex,
		"AllowSystemAccessRightUlong":            FormHex,
		"CallerLogonId":                          FormHex,
		"CallerProcessId":                        FormHex,
		"DenySystemAccessRightUlong":             FormHex,
		"EAPErrorCode":                           FormHex,
		"EAPReasonCode":                          FormHex,
		"ErrorCode":                              FormDecimal,
		"EtherType":                              FormHex,
		"EventSourceId":                          FormHex,
		"FailureId":                              FormHex,
		"FailureReason":                          FormText,
		"FinalAccessRightsMask":                  FormHex,
		"GrantedAccessRightsMask":                FormHex,
		"HandleId":                               FormHex,
		"LogonID":                                FormHex,
		"NewMaxUsers":                            FormHex,
		"NewProcessId":                           FormHex,
		"NewShareFlags":                          FormHex,
		"NewValue":                               FormText,
		"OldMaxUsers":                            FormHex,
		"OldShareFlags":                          FormHex,
		"OldValue":                               FormHex,
		"OperationId":                            FormHex,
		"OriginalAccessRightsMask":               FormHex,
		"Position":                               FormHex,
		"ProcessId":                              FormHex,
		"ProtectedDataFlags":                     FormHex,
		"PuaPolicyId":                            FormHex,
		"ReasonCode":                             FormText,
		"RecoveryReason":                         FormHex,
		"RemovedAccessRightsMask":                FormHex,
		"ReturnCode":                             FormHex,
		"ServiceType":                            FormHex,
		"SourceHandleId":                         FormHex,
		"SourceProcessId":                        FormHex,
		"Status":                                 FormHex,
		"SubStatus":                              FormHex,
		"SubjectLogonId":                         FormHex,
		"SystemAccessRightRequiredForLogonUlong": FormHex,
		"TargetHandleId":                         FormHex,
		"TargetLinkedLogonId":                    FormHex,
		"TargetLogonId":                          FormHex,
		"TargetProcessId":                        FormHex,
		"TicketEncryptionType":                   FormHex,
		"TicketOptions":                          FormHex,
		"VlanTag":                                FormHex,
	},
	Events: map[int]map[string]Form{
		4657: {"OldValue": FormText},
		4665: {"Status": FormDecimal},
		4666: {"OperationId": FormDecimal},
		4674: {"AccessMask": FormText},
		4692: {"FailureReason": FormHex},
		4694: {"FailureReason": FormHex},
		4695: {"FailureReason": FormHex},
		4766: {"SubjectLogonId": FormText},
		4772: {"TicketOptions": FormText},
		4773: {"TicketOptions": FormText},
		4777: {"Status": FormText},
		5050: {"ProcessId": FormDecimal},
		5065: {"NewValue": FormHex},
		5067: {"NewValue": FormHex},
		5070: {"OldValue": FormText},
		5125: {"Status": FormText},
		5152: {"ProcessId": FormDecimal},
		5153: {"ProcessId": FormDecimal},
		5154: {"ProcessId": FormDecimal},
		5155: {"ProcessId": FormDecimal},
		5158: {"ProcessId": FormDecimal},
		5159: {"ProcessId": FormDecimal},
		5168: {"ErrorCode": FormHex},
		5379: {"ReturnCode": FormDecimal},
		5382: {"ReturnCode": FormDecimal},
		5446: {"ProcessId": FormDecimal},
		5447: {"ProcessId": FormDecimal},
		5448: {"ProcessId": FormDecimal},
		5449: {"ProcessId": FormDecimal},
		5450: {"ProcessId": FormDecimal},
		5632: {"ErrorCode": FormHex, "ReasonCode": FormHex},
		5633: {"ErrorCode": FormHex, "ReasonCode": FormHex},
		5712: {"ProcessId": FormDecimal},
	},
}

var eventlogManifest = manifest{
	Fields: map[string]Form{
		"Reason":         FormDecimal,
		"SubjectLogonId": FormHex,
	},
	Events: map[int]map[string]Form{
		1106: {"Reason": FormHex},
	},
}

var sysmonManifest = manifest{
	Fields: map[string]Form{
		"GrantedAccess": FormHex,
		"LogonId":       FormHex,
	},
}
