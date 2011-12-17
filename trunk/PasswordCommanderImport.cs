using System;
using System.Collections;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using System.Xml.XPath;
using KeePass.DataExchange;
using KeePass.Resources;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;

namespace PasscommImport
{
	using System.Diagnostics;
	using System.Text.RegularExpressions;
	using KeePassLib.Collections;

	internal enum PasscommFieldType
	{
		Login = 0,
		Password = 1,
		URL = 2,
		CMD = 3,
		Email = 4,
		File = 5,
		Text = 6,
		AdditionalPassword = 7,
		IP = 8
	}

	internal sealed class PasscommImportCSV : FileFormatProvider
	{
		private bool m_bHasAutoTypePlugin = false;

		public override bool SupportsImport
		{
			get
			{
				return true;
			}
		}
		public override bool SupportsExport
		{
			get
			{
				return false;
			}
		}

		public override string FormatName
		{
			get
			{
				return "Password Commander CSV";
			}
		}
		public override string DefaultExtension
		{
			get
			{
				return "csv";
			}
		}
		public override string ApplicationGroup
		{
			get
			{
				return KPRes.PasswordManagers;
			}
		}

		public override Image SmallIcon
		{
			get
			{
				Bitmap bmpImage = Properties.Resources.PassCmdIcon;
				bmpImage.MakeTransparent();

				return bmpImage;
			}
		}

		public PasscommImportCSV( bool bHasAutoTypePlugin )
		{
			m_bHasAutoTypePlugin = bHasAutoTypePlugin;
		}

		public override void Import( PwDatabase pwStorage, Stream sInput, IStatusLogger slLogger )
		{
			var docXml = LoadFile( sInput );

			//docXml.Save( "Dump.xml" );

			foreach( XElement xelGroup in docXml.XPathSelectElements( "Account/Group" ) )
			{
				AddGroup( xelGroup, pwStorage.RootGroup );
			}

		}

		internal XDocument LoadFile( Stream sFile )
		{
			var xelRoot = new XElement( "Account" );
			var docXml = new XDocument( xelRoot );

			var reader = new StreamReader( sFile, Encoding.Default );
			var parsed = CsvParser.Parse( reader.ReadToEnd(), ';' );

			int iLineNum = 0;
			int iRecordLine = 0;
			int iRecordType = -1;
			int iLevel = 0;
			bool bInsideRecord = false;
			bool bInsideFiles = false;

			XElement xelCurrent = null;

			foreach ( var line in parsed )
			{
				if ( line.Length == 0 )
				{
					continue;
				}

				if ( line.Length == 1 )
				{
					string sLine = line[0];
					if ( iLineNum == 0 )
					{
						if ( !sLine.StartsWith( "Password Commander" ) )
						{
							throw new Exception( "Not a Password Commander CSV file" );
						}
						iLevel = -1;
					}
					else if ( iLevel == -1 )
					{
						iLevel++;
						string sAccount = sLine.Split( ':' )[1].Trim();
						xelRoot.Add( new XAttribute( "Name", sAccount ) );
					}
					else if ( iLevel >= 0 )
					{
						// skip empty
						if ( string.IsNullOrEmpty( sLine ) )
						{
							continue;
						}
						if ( sLine.StartsWith( "-----" ) )
						{
							if ( sLine == "---------------" ) // end of record
							{
								bInsideRecord = false;
							}
							else // start of record
							{
								iRecordLine = 0;
								iRecordType = -1;
								bInsideRecord = true;
							}
						}
						else if ( bInsideRecord )
						{
							iRecordLine++;
						}
						else
						{
							bInsideFiles = true;
							xelCurrent = new XElement( "Files" );
							xelRoot.Add( xelCurrent );
						}
					}
					else
					{
						throw new Exception( "Malformed Password Commander CSV file" );
					}
				}
				else
				{
					if ( !bInsideRecord && !bInsideFiles )
					{
						throw new Exception( "Malformed Password Commander CSV file" );
					}

					if ( bInsideRecord )
					{
						if ( iRecordLine == 0 && iRecordType == -1 )
						{
							iRecordType = int.Parse( line[0] );
						}

						int iKey = iRecordLine << 16 | iRecordType;

						switch ( iKey )
						{
						case 0 << 16 | 0: // first line, group type
							{
								xelCurrent = new XElement( "Group",
									new XElement( "Name", line[1] ),
									new XElement( "Comment", line[2] )
									);

								xelRoot.Add( xelCurrent );
							}
							break;
						case 1 << 16 | 0: // 2-nd line, group type
							{
								var xelFields = new XElement( "Fields" );
								
								Debug.Assert( xelCurrent != null, "xelCurrent != null" );

								xelCurrent.Add( xelFields );
								for ( int i = 1; i < line.Length; i++ )
								{
									xelFields.Add( new XElement( "Field",
										new XAttribute( "Id", i - 1 ),
										new XAttribute( "Type", line[i] )
										) );
								}
							}
							break;
						case 2 << 16 | 0: // 3-rd line, group type
							{
								Debug.Assert( xelCurrent != null, "xelCurrent != null" );
								for ( int i = 1; i < line.Length; i++ )
								{
									var xelField = xelCurrent.XPathSelectElement( string.Format( "Fields/Field[@Id={0}]", i - 1 ) );
									xelField.Add( new XAttribute( "Name", line[i] ) );
								}
							}
							break;
						case 3 << 16 | 0: // 4-th line, group type
							{
								var xelDefaults = new XElement( "Defaults" );
								
								Debug.Assert( xelCurrent != null, "xelCurrent != null" );

								xelCurrent.Add( xelDefaults );
								for ( int i = 1; i < line.Length; i++ )
								{
									var xelField = xelCurrent.XPathSelectElement( string.Format( "Fields/Field[@Name='{0}']", line[i] ) );
									if ( xelField != null )
									{
										var xAttribute = xelField.Attribute( XName.Get( "Id" ) );
										if ( xAttribute != null )
										{
											xelDefaults.Add( new XElement( "Value",
												new XAttribute( "Id", xAttribute.Value ),
												new XAttribute( "Name", line[i] ),
												"Missed!" //bug in Password Commander exporter? No default values exported.
												) );
										}
									}
								}
							}
							break;
						case 4 << 16 | 0: // 5-th line, group type
							{
								Debug.Assert( xelCurrent != null, "xelCurrent != null" );

								xelCurrent.Add(
									new XElement( "ValidTill", string.IsNullOrEmpty( line[1] ) ? null : DateTime.Parse( line[1] ).ToShortDateString() ),
									new XElement( "ValidDays", string.IsNullOrEmpty( line[3] ) ? null : line[3] ),
									new XElement( "AutoType", string.IsNullOrEmpty( line[7] ) ? null : line[7] )
									);
							}
							break;

							// folder
						case 0 << 16 | 1: // first line, folder type
							{
								xelCurrent = new XElement( "Folder",
									new XElement( "Name", line[1] ),
									new XElement( "Comment", line[3] )
									);

								int iLvl = int.Parse( line[2] );

								XElement xelParent = xelRoot;

								for ( int i = 0; i < iLvl; i++ )
								{
									xelParent = xelParent.XPathSelectElements( "Group | Folder" ).Last();
								}
								xelParent.Add( xelCurrent );
							}
							break;

							// record
						case 0 << 16 | 2: // first line, record type
							{
								xelCurrent = new XElement( "Record",
									new XElement( "Name", line[1] ),
									new XElement( "Comment", line[3] )
									);

								int iLvl = int.Parse( line[2] );

								XElement xelParent = xelRoot;

								for ( int i = 0; i < iLvl; i++ )
								{
									xelParent = xelParent.XPathSelectElements( "Group | Folder" ).Last();
								}
								xelParent.Add( xelCurrent );
							}
							break;
						case 1 << 16 | 2: // 2-nd line, record type
							{
								var xelValues = new XElement( "Values" );
								
								Debug.Assert( xelCurrent != null, "xelCurrent != null" );

								xelCurrent.Add( xelValues );

								var xelGroup = xelRoot.Elements( "Group" ).Last();

								for ( int i = 1; i < line.Length; i++ )
								{
									var xelField = xelGroup.XPathSelectElement( string.Format( "Fields/Field[@Id={0}]", i - 1 ) );

									if ( xelField != null )
									{
										var xAttrType = xelField.Attribute( XName.Get( "Type" ) );
										var xAttrName = xelField.Attribute( XName.Get( "Name" ) );
										if ( xAttrType != null && xAttrName != null )
										{
											xelValues.Add( new XElement( "Value",
												new XAttribute( "Id", i - 1 ),
												new XAttribute( "Type", xAttrType.Value ),
												new XAttribute( "Name", xAttrName.Value ),
												line[i]
												) );
										}
									}
								}
							}
							break;
						case 2 << 16 | 2: // 3-rd line, record type
							{
								Debug.Assert( xelCurrent != null, "xelCurrent != null" );

								xelCurrent.Add(
									new XElement( "Modified", string.IsNullOrEmpty( line[2] ) ? null : DateTime.Parse( line[2] ).ToShortDateString() ),
									new XElement( "ValidTill", string.IsNullOrEmpty( line[1] ) ? null : DateTime.Parse( line[1] ).ToShortDateString() ),
									new XElement( "ValidDays", string.IsNullOrEmpty( line[3] ) ? null : line[3] )
									);

								var xelAutoType = new XElement( "AutoType" );

								xelCurrent.Add( xelAutoType );

								string[] arrSequences = line[6].Normalize().Split( 
									new[]
									{
										"%%#"
									}, 
									StringSplitOptions.None );

								foreach ( var val in arrSequences )
								{
									string[] arrVals = val.Split( 
										new[]
										{
											"||"
										}, 
										StringSplitOptions.None );

									xelAutoType.Add(
										new XElement( "Rule",
											new XAttribute( "Type", arrVals[1] ),
											new XAttribute( "UseMask", arrVals[0] ),
											new XElement( "Match", arrVals[2].Trim() ),
											new XElement( "Sequence", arrVals[3].TrimEnd( '\a', '\v', '\x03' ) )
											)
										);
								}
							}
							break;
						}
						iRecordLine++;
					}
					else
					{
						xelCurrent.Add( new XElement( "File",
							new XAttribute( "Key", line[1] ),
							new XElement( "Value", line[2] )
							//new XElement( "ValueCompressed", Convert.ToBase64String( Compress( Convert.FromBase64String( line[2] ) ) ) )
							) );
					}
				}
				iLineNum++;
			}

			return docXml;
		}

		private void AddGroup( XElement xelGroup, PwGroup objRoot )
		{
			if ( xelGroup == null )
			{
				throw new ArgumentNullException( "xelGroup" );
			}

			string sName = GetString( xelGroup, "Name" );

			var objGroup = new PwGroup( true, true, string.IsNullOrEmpty( sName ) ? "Unknown" : sName, PwIcon.FolderPackage )
				{
					Notes = GetString( xelGroup, "Comment", true )
				};

			DateTime dtValid;

			if( DateTime.TryParse( GetString( xelGroup, "ValidTill" ), out dtValid ) )
			{
				objGroup.Expires = true;
				objGroup.ExpiryTime = dtValid;
			}

			string aAutoType = GetString( xelGroup, "AutoType" );
			if( !string.IsNullOrEmpty( aAutoType ) )
			{
				objGroup.DefaultAutoTypeSequence = ConvertAutoType( aAutoType, xelGroup );
			}
			objRoot.AddGroup( objGroup, true );

			foreach( XElement xelFolder in xelGroup.XPathSelectElements( "Folder" ) )
			{
				AddFolder( xelFolder, objGroup );
			}

			foreach( XElement xelRecord in xelGroup.XPathSelectElements( "Record" ) )
			{
				AddRecord( xelRecord, objGroup );
			}

		}

		private void AddFolder( XElement xelFolder, PwGroup objParent )
		{
			if ( xelFolder == null )
			{
				throw new ArgumentNullException( "xelFolder" );
			}

			string sName = GetString( xelFolder, "Name" );

			var objGroup = new PwGroup( true, true, string.IsNullOrEmpty( sName ) ? "Unknown" : sName, PwIcon.Folder )
				{
					Notes = GetString( xelFolder, "Comment", true )
				};

			objParent.AddGroup( objGroup, true );

			foreach( XElement xelSubFolder in xelFolder.XPathSelectElements( "Folder" ) )
			{
				AddFolder( xelSubFolder, objGroup );
			}

			foreach( XElement xelRecord in xelFolder.XPathSelectElements( "Record" ) )
			{
				AddRecord( xelRecord, objGroup );
			}

		}

		private void AddRecord( XElement xelRecord, PwGroup objParent )
		{
			if ( xelRecord == null )
			{
				throw new ArgumentNullException( "xelRecord" );
			}

			var objEntry = new PwEntry( true, true );

			objEntry.Strings.Set( PwDefs.TitleField, new ProtectedString( false, GetString( xelRecord, "Name" ) ) );
			objEntry.Strings.Set( PwDefs.NotesField, new ProtectedString( false, GetString( xelRecord, "Comment", true ) ) );

			foreach( var xelValue in xelRecord.XPathSelectElements( "Values/Value" ) )
			{
				var eType = (PasscommFieldType) int.Parse( GetString( xelValue, "@Type" ) );

				switch ( eType )
				{
				case PasscommFieldType.Login:
					{
						objEntry.Strings.Set( PwDefs.UserNameField, new ProtectedString( false, xelValue.Value ) );
					}
					break;
				case PasscommFieldType.Password:
					{
						objEntry.Strings.Set( PwDefs.PasswordField, new ProtectedString( true, xelValue.Value ) );
					}
					break;
				case PasscommFieldType.URL:
					{
						objEntry.Strings.Set( PwDefs.UrlField, new ProtectedString( false, xelValue.Value ) );
					}
					break;
				case PasscommFieldType.CMD:
				case PasscommFieldType.Email:
				case PasscommFieldType.Text:
				case PasscommFieldType.IP:
					{
						objEntry.Strings.Set( GetString( xelValue, "@Name" ), new ProtectedString( false, xelValue.Value ) );
					}
					break;
				case PasscommFieldType.AdditionalPassword:
					{
						objEntry.Strings.Set( GetString( xelValue, "@Name" ), new ProtectedString( true, xelValue.Value ) );
					}
					break;
				case PasscommFieldType.File:
					{
						if ( !string.IsNullOrEmpty( xelValue.Value ) )
						{
							string[] arrFile = xelValue.Value.Split( '|' );

							Debug.Assert( xelRecord.Document != null, "xelRecord.Document != null" );

							objEntry.Binaries.Set( arrFile[0],
								new ProtectedBinary( true,
									Convert.FromBase64String(
										GetString(
											xelRecord.Document.Root,
											string.Format( "Files/File[@Key='{0}']", arrFile[1] )
											)
										)
									) );
						}
					}
					break;
				}
			}

			var xelGroup = xelRecord;
			while ( xelGroup.Name.LocalName != "Group" && xelGroup.Parent != null )
			{
				xelGroup = xelGroup.Parent;
			}

			bool bEnableAutoType = false;

			if ( xelGroup.Name.LocalName == "Group" )
			{
				foreach ( var xRule in xelRecord.XPathSelectElements( "AutoType/Rule" ) )
				{
					int iType = int.Parse( GetString( xRule, "@Type" ) );
					if ( iType != 0 )
					{
						string sMatch = GetString( xRule, "Match" );
						string sSequence = GetString( xRule, "Sequence" );

						if ( iType != 1 )
						{
							sMatch = "??:URL:" + sMatch;
						}

						if ( !string.IsNullOrEmpty( sMatch ) && !string.IsNullOrEmpty( sSequence ) )
						{
							sSequence = ConvertAutoType( sSequence, xelGroup );
							if (!string.IsNullOrEmpty( sSequence ))
							{
								bEnableAutoType = true;
								objEntry.AutoType.Add( new AutoTypeAssociation( sMatch, sSequence ) );
							}
						}
					}
				}
			}

			objEntry.AutoType.Enabled = bEnableAutoType;

			DateTime dtValid;
			if ( DateTime.TryParse( GetString( xelGroup, "ValidTill" ), out dtValid ) )
			{
				objEntry.Expires = true;
				objEntry.ExpiryTime = dtValid;
			}

			objParent.AddEntry( objEntry, true );
		}

		private static string GetString( XElement xelElement, string sXPath )
		{
			return GetString( xelElement, sXPath, false );
		}

		private static string GetString( XElement xelElement, string sXPath, bool bReplaceSpecials )
		{
			string sValue = string.Empty;

			if( xelElement == null )
			{
				return sValue;
			}

			var evalResult = (IEnumerable) xelElement.XPathEvaluate( sXPath );
			var enumerator = evalResult.GetEnumerator();
			enumerator.MoveNext();

			object elem = enumerator.Current;
			if( elem != null )
			{
				if( elem is XElement )
				{
					sValue =( (XElement) elem ).Value;
				}
				else if( elem is XAttribute )
				{
					sValue = ( (XAttribute) elem ).Value;
				}
				else if( elem is XCData )
				{
					sValue =( (XCData) elem ).Value;
				}
			}
			return bReplaceSpecials ? sValue.Replace( "&linebreak;", Environment.NewLine ) : sValue;
		}


		private static string ConvertAutoType( string sSequence, XElement xelGroup )
		{
			try
			{
				return Regex.Replace( sSequence, @"(?:([+^~()])|\{(m?(?:Clear|Tab|Enter|Esc|Space|Up|Down|Right|Left|Shift\+Tab))(\d*)\}|%([^%]+)%)",
					objMatch => 
						{
							string sSpecialChar = objMatch.Groups[1].Success ? objMatch.Groups[1].Value : null;
							string sCommandName = objMatch.Groups[2].Success ? objMatch.Groups[2].Value : null;
							int iFieldCount = objMatch.Groups[3].Success && !string.IsNullOrEmpty( objMatch.Groups[3].Value ) ? int.Parse( objMatch.Groups[3].Value ) : 0;

							string sFieldName = objMatch.Groups[4].Success ? objMatch.Groups[4].Value : null;
							if ( sSpecialChar != null )
							{
								return "{" + sSpecialChar + "}";
							}
							
							if ( sCommandName != null )
							{
								switch ( sCommandName.ToUpper() )
								{
								case "CLEAR":
									return "{CLEARFIELD}";
								case "TAB":
									return iFieldCount > 0 ? string.Format( "{{TAB {0}}}", iFieldCount ) : "{TAB}";
								case "ENTER":
									return iFieldCount > 0 ? string.Format( "{{ENTER {0}}}", iFieldCount ) : "{ENTER}";
								case "ESC":
									return iFieldCount > 0 ? string.Format( "{{ESC {0}}}", iFieldCount ) : "{ESC}";
								case "SPACE":
									return " ";
								case "UP":
									return iFieldCount > 0 ? string.Format( "{{UP {0}}}", iFieldCount ) : "{UP}";
								case "DOWN":
									return iFieldCount > 0 ? string.Format( "{{DOWN {0}}}", iFieldCount ) : "{DOWN}";
								case "RIGHT":
									return iFieldCount > 0 ? string.Format( "{{RIGHT {0}}}", iFieldCount ) : "{RIGHT}";
								case "LEFT":
									return iFieldCount > 0 ? string.Format( "{{LEFT {0}}}", iFieldCount ) : "{LEFT}";
								case "SHIFT+TAB":
									return iFieldCount > 0 ? string.Format( "+{{TAB {0}}}", iFieldCount ) : "+{TAB}";
								}
							}
							else if ( sFieldName != null )
							{
								if ( sFieldName == "Record Name" )
								{
									return "{TITLE}";
								}

								var xelField = xelGroup.XPathSelectElement( string.Format( "Fields/Field[@Name='{0}']", sFieldName ) );

								if ( xelField != null )
								{
									var xAttrType = xelField.Attribute( XName.Get( "Type" ) );
									if ( xAttrType != null )
									{
										var enFieldTyper = (PasscommFieldType) int.Parse( xAttrType.Value );
										switch ( enFieldTyper )
										{
										case PasscommFieldType.Login:
											return "{USERNAME}";
										case PasscommFieldType.Password:
											return "{PASSWORD}";
										case PasscommFieldType.URL:
											{
												var xnlUrls = xelGroup.XPathSelectElements( string.Format( "Fields/Field[@Type='{0}']", (int) enFieldTyper ) );
												if ( xnlUrls.Count() > 0 && xnlUrls.First() == xelField )
												{
													return "{URL}";
												}
												return string.Format( "{{S:{0}}}", sFieldName );
											}
										default:
											return string.Format( "{{S:{0}}}", sFieldName );
										}
									}
								}
							}
							throw new Exception( "Bad field reference found" );
						},
						RegexOptions.IgnoreCase
					);
			}
			catch ( Exception e )
			{
				return string.Empty;
			}
		}

	}
}
