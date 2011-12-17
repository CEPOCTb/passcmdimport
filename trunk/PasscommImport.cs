using System.Diagnostics;
using System.IO;
using KeePass.Plugins;

namespace PasscommImport
{
	public sealed class PasscommImportExt : Plugin
	{
		// The sample plugin remembers its host in this variable.
		private IPluginHost m_host;
		private PasscommImportCSV m_Importer;

		public override bool Initialize(IPluginHost host)
		{
			Debug.Assert( host != null );
			
			if( host == null )
				return false;
			
			m_host = host;

			string sPath = Path.Combine( System.AppDomain.CurrentDomain.BaseDirectory, "WebAutoType.dll" );

			m_Importer = new PasscommImportCSV( File.Exists( sPath ) );

			m_host.FileFormatPool.Add( m_Importer );

			return true;
		}
		
		public override void Terminate()
		{
			m_host.FileFormatPool.Remove( m_Importer );
		}

	}
}
