using System;
using System.Collections.Generic;
using System.Text;

namespace PasscommImport
{
	public static class CsvParser
	{
		public static List<string[]> Parse( string sInputString, char cSeparator )
		{
			var result = new List<string[]>();
			var current = new List<string>();

			var builder = new StringBuilder();

			int iLength = sInputString.Length;
			bool bInsideQuotas = false;
			int iLine = 0;
			int iPos = 0;

			for( int i = 0; i < iLength; i++, iPos++ )
			{
				if( sInputString[i] == '"' )
				{
					if ( i + 1 < iLength && sInputString[i + 1] == '"' ) // escaped "
					{
						i++;
						char ch = i >= 2 ? sInputString[i - 2] : '\0';
						char ch2 = i < iLength - 1 ? sInputString[i + 1] : '\0';
						if ( ( ch == '\0' || ch == '\r' || ch == '\n' || ch == cSeparator ) &&
							(ch2 == '\0' || ch2 == '\r' || ch2 == '\n' || ch2 == cSeparator))
						{
							continue;
						}
						builder.Append('"');
					}
					else if( !bInsideQuotas )
					{
						bInsideQuotas = true;
					}
					else if ( i + 1 < iLength && ( sInputString[i + 1] == cSeparator || sInputString[i+1] == '\r' || sInputString[i+1] == '\n' ) )
					{
						bInsideQuotas = false;
					}
					else
					{
						throw new Exception( string.Format( "Malformed CSV, line: {0}, position: {1}", iLine, iPos ) );
					}
				}
				else if( sInputString[i] == cSeparator )
				{
					if( bInsideQuotas )
					{
						builder.Append( sInputString[i] );
					}
					else
					{
						current.Add( builder.ToString() );
						builder = new StringBuilder();
					}
				}
				else if ( sInputString[i] == '\r' || sInputString[i] == '\n' )
				{
					if( bInsideQuotas )
					{
						builder.Append( sInputString[i] );
					}
					else
					{
						current.Add( builder.ToString() );
						result.Add( current.ToArray() );
						current = new List<string>();
						builder = new StringBuilder();
						iPos = 0;
					}
					if ( i + 1 < iLength &&
						( 
							( sInputString[i] == '\r' && sInputString[i + 1] == '\n' )
							|| ( sInputString[i] == '\n' && sInputString[i + 1] == '\r' ))
						)
					{
						i++;
						if( bInsideQuotas )
						{
							builder.Append( sInputString[i] );
						}
					}
					iLine++;
				}
				else
				{
					builder.Append( sInputString[i] );
				}
			}

			if( bInsideQuotas )
			{
				throw new Exception( string.Format( "Malformed CSV, '\"' expected at the end of line {0}" , iLine ) );
			}

			current.Add( builder.ToString() );
			result.Add( current.ToArray() );
			return result;
		}
	}
}
