pub const PREFERENCES_XML_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Preferences>
<OSCAR>
 <Preferences>
  <Fonts_Application_Size type="int">10</Fonts_Application_Size>
  <Updates_AutoCheck type="bool">true</Updates_AutoCheck>
  <Fonts_Graph_Italic type="bool">false</Fonts_Graph_Italic>
  <RightSidebarVisible type="bool">false</RightSidebarVisible>
  <ShowSerialNumbers type="bool">false</ShowSerialNumbers>
  <SquareWavePlots type="bool">false</SquareWavePlots>
  <OverlayType type="int">0</OverlayType>
  <ShowAboutDialog type="int">-1</ShowAboutDialog>
  <UsePixmapCaching type="bool">false</UsePixmapCaching>
  <Fonts_Graph_Name type="QString">Noto Sans</Fonts_Graph_Name>
  <Fonts_Title_Bold type="bool">true</Fonts_Title_Bold>
  <RightPanelWidth type="double">230</RightPanelWidth>
  <Fonts_Application_Bold type="bool">false</Fonts_Application_Bold>
  <GraphTooltips type="bool">true</GraphTooltips>
  <LineThickness type="QString">1</LineThickness>
  <Fonts_Graph_Size type="int">10</Fonts_Graph_Size>
  <ShowPersonalData type="bool">true</ShowPersonalData>
  <UserEventPieChart type="bool">false</UserEventPieChart>
  <OverviewLinechartMode type="int">0</OverviewLinechartMode>
  <NotifyMessagBoxOption type="bool">false</NotifyMessagBoxOption>
  <AutoOpenLastUsed type="bool">true</AutoOpenLastUsed>
  <ScrollDampening type="int">50</ScrollDampening>
  <IncludeSerial type="bool">false</IncludeSerial>
  <LineCursorMode type="bool">true</LineCursorMode>
  <OpenTabAfterImport type="int">2</OpenTabAfterImport>
  <RemoveCardReminder type="bool">true</RemoveCardReminder>
  <Fonts_Title_Name type="QString">Noto Sans</Fonts_Title_Name>
  <GraphHeight type="int">180</GraphHeight>
  <AllowYAxisScaling type="bool">true</AllowYAxisScaling>
  <Fonts_Big_Italic type="bool">false</Fonts_Big_Italic>
  <EnablePieChart type="bool">false</EnablePieChart>
  <PrintBW type="bool">false</PrintBW>
  <Fonts_Big_Size type="int">35</Fonts_Big_Size>
  <AlternatingColorsCombo type="int">0</AlternatingColorsCombo>
  <ShowPerformance type="bool">false</ShowPerformance>
  <ShowDebug type="bool">false</ShowDebug>
  <Updates_CheckFrequency type="int">14</Updates_CheckFrequency>
  <AutoLaunchImport type="bool">true</AutoLaunchImport>
  <Fonts_Title_Size type="int">12</Fonts_Title_Size>
  <MemoryHog type="bool">false</MemoryHog>
  <DisableDailyGraphTitles type="bool">false</DisableDailyGraphTitles>
  <EnableMultithreading type="bool">false</EnableMultithreading>
  <TooltipTimeout type="int">2500</TooltipTimeout>
  <CalendarVisible type="bool">false</CalendarVisible>
  <DontAskWhenSavingScreenshots type="bool">false</DontAskWhenSavingScreenshots>
  <Fonts_Big_Name type="QString">Noto Sans</Fonts_Big_Name>
  <AllowEarlyUpdates type="bool">false</AllowEarlyUpdates>
  <Fonts_Big_Bold type="bool">false</Fonts_Big_Bold>
  <Profile type="QString">{USERNAME}</Profile>
  <OpenTabAtStart type="int">2</OpenTabAtStart>
  <Fonts_Application_Name type="QString">Sans Serif</Fonts_Application_Name>
  <AnimationsAndTransitions type="bool">true</AnimationsAndTransitions>
  <SteadyBreathing type="int">0</SteadyBreathing>
  <DailyPanelWidth type="double">250</DailyPanelWidth>
  <Fonts_Graph_Bold type="bool">false</Fonts_Graph_Bold>
  <UseAntiAliasing type="bool">true</UseAntiAliasing>
  <VersionString type="QString">{VERSION}</VersionString>
  <Language type="QString">en_US</Language>
  <Fonts_Application_Italic type="bool">false</Fonts_Application_Italic>
  <Fonts_Title_Italic type="bool">false</Fonts_Title_Italic>
 </Preferences>
</OSCAR>
"#;

pub const PROFILE_XML_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Profile>
<OSCAR>
 <Profile>
  <UserEventDuration2 type="QString">8</UserEventDuration2>
  <CalculateUnintentionalLeaks type="bool">true</CalculateUnintentionalLeaks>
  <LockSummarySessions type="bool">true</LockSummarySessions>
  <TimeZone type="QString">Pacific/Midway</TimeZone>
  <flagPulseAbove type="double">99</flagPulseAbove>
  <SyncOximeterClock type="bool">true</SyncOximeterClock>
  <EnableOximetry type="bool">false</EnableOximetry>
  <AutoImport type="bool">true</AutoImport>
  <ComplianceHours type="QString">4</ComplianceHours>
  <MaskDescription type="QString"></MaskDescription>
  <Address type="QString"></Address>
  <oxiDesaturationThreshold type="double">88</oxiDesaturationThreshold>
  <BrickWarning type="bool">true</BrickWarning>
  <Height type="double">0.0</Height>
  <UserFlowRestriction type="QString">20</UserFlowRestriction>
  <PulseChangeDuration type="double">8</PulseChangeDuration>
  <UnitSystem type="int">1</UnitSystem>
  <BackupCardData type="bool">false</BackupCardData>
  <EventPostcontext type="double">0</EventPostcontext>
  <PulseChangeBPM type="double">5</PulseChangeBPM>
  <ShowLeakRedline type="bool">true</ShowLeakRedline>
  <LastOverviewRange type="int">4</LastOverviewRange>
  <AHIReset type="bool">false</AHIReset>
  <WarnOnUnexpectedData type="bool">true</WarnOnUnexpectedData>
  <PrefCalcMiddle type="int">0</PrefCalcMiddle>
  <SkipOxiIntroScreen type="bool">false</SkipOxiIntroScreen>
  <DoctorPatientID type="QString"></DoctorPatientID>
  <SPO2DropPercentage type="double">3</SPO2DropPercentage>
  <UserName type="QString">{USERNAME}</UserName>
  <Phone type="QString"></Phone>
  <EventWindowSize type="double">3</EventWindowSize>
  <DoctorAddress type="QString"></DoctorAddress>
  <OximeterType type="int">0</OximeterType>
  <CPAPPrescribedMaxPressure type="QString">0</CPAPPrescribedMaxPressure>
  <StatReportMode type="int">0</StatReportMode>
  <PrefCalcMax type="int">1</PrefCalcMax>
  <Custom20cmH2OLeaks type="double">48.3</Custom20cmH2OLeaks>
  <UserEventDuration type="QString">8</UserEventDuration>
  <DefaultOxiDevice type="QString"></DefaultOxiDevice>
  <WarnOnUntestedMachine type="bool">true</WarnOnUntestedMachine>
  <ShowUnknownFlags type="bool">false</ShowUnknownFlags>
  <IgnoreOlderSessions type="bool">false</IgnoreOlderSessions>
  <DoctorEmail type="QString"></DoctorEmail>
  <UserEventDuplicates type="bool">false</UserEventDuplicates>
  <DoctorName type="QString"></DoctorName>
  <UserFlowRestriction2 type="QString">50</UserFlowRestriction2>
  <CPAPPrescribedMode type="int">0</CPAPPrescribedMode>
  <flagPulseBelow type="double">40</flagPulseBelow>
  <Language type="QString">en_US</Language>
  <UserEventFlagging type="bool">false</UserEventFlagging>
  <EmailAddress type="QString"></EmailAddress>
  <LeakRedline type="QString">24</LeakRedline>
  <LastName type="QString"></LastName>
  <SkipEmptyDays type="bool">true</SkipEmptyDays>
  <MaskStartDate type="QString"></MaskStartDate>
  <ResyncFromUserFlagging type="bool">false</ResyncFromUserFlagging>
  <RebuildCache type="bool">false</RebuildCache>
  <PrefCalcPercentile type="double">95</PrefCalcPercentile>
  <ClinicalMode type="bool">true</ClinicalMode>
  <DaySplitTime type="QTime">12:00:00</DaySplitTime>
  <EventFlagSessionBar type="bool">false</EventFlagSessionBar>
  <Password type="QString"></Password>
  <MaskType type="int">0</MaskType>
  <PreloadSummaries type="bool">false</PreloadSummaries>
  <ClockDrift type="int">0</ClockDrift>
  <CalculateRDI type="bool">false</CalculateRDI>
  <CPAPNotes type="QString"></CPAPNotes>
  <DataFolder type="QString">{home}/Profiles/{UserName}</DataFolder>
  <CompressBackupData type="bool">false</CompressBackupData>
  <IgnoreShorterSessions type="double">0</IgnoreShorterSessions>
  <OxiDiscardThreshold type="double">0</OxiDiscardThreshold>
  <baseSpO2Option type="int">0</baseSpO2Option>
  <FirstName type="QString"></FirstName>
  <DoctorPractice type="QString"></DoctorPractice>
  <ShowLeaksMode type="int">0</ShowLeaksMode>
  <VersionString type="QString">{VERSION}</VersionString>
  <LastCPAPPath type="QString">/config/Documents/SDCARD</LastCPAPPath>
  <CPAPPrescribedMinPressure type="QString">0</CPAPPrescribedMinPressure>
  <DoctorPhone type="QString"></DoctorPhone>
  <ZombieMode type="bool">false</ZombieMode>
  <SPO2DropDuration type="double">8</SPO2DropDuration>
  <AHIWindow type="QString">60</AHIWindow>
  <UntreatedAHI type="QString">0</UntreatedAHI>
  <CompressSessionData type="bool">false</CompressSessionData>
  <ConsolidateEvents type="bool">false</ConsolidateEvents>
  <Custom4cmH2OLeaks type="double">20.1</Custom4cmH2OLeaks>
  <DST type="bool">false</DST>
  <CombineCloserSessions type="double">0</CombineCloserSessions>
  <Gender type="int">0</Gender>
  <Country type="QString">Select Country</Country>
 </Profile>
</OSCAR>
"#;

pub const OSCAR_CONF_TEMPLATE: &str = r#"[General]

[MainWindow]

[Settings]
AppData=/config/Documents/OSCAR_Data
Language=en_US
"#;
