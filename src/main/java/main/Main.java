package main;

import com.dream.demo.CSCADemo;
import com.dream.demo.CVCADemo; 

public class Main {

	
	public static void main(String[] args) throws Exception {	
		
		runCSCADemo();

		//runCVCADemo();
		
		System.exit(0);

	}
	
	public static void runCSCADemo() throws Exception {
		CSCADemo cscaDemo = new CSCADemo();
		
		// gen csca certificate
		//cscaDemo.createCSCACert();
				
		// gen link certificate
		//cscaDemo.createLinkCert(cscaDemo.NEXT_CSCA_DN);
		
		// gen pkcs10 request		
		//cscaDemo.createPKCS10Request(cscaDemo.END_ENTITY_SUB_DN);
		
		// gen ds cert
		//cscaDemo.createDSCertWithDocType();
		
		// gen master list signer
		//cscaDemo.createMasterListSignerCert();
		
		// gen dev list signer
		//cscaDemo.createDeviationListSignerCert();
		
		// get crl 
		//cscaDemo.createCRL();
				
		// gen master list
		//cscaDemo.createMasterList();
		
		// gen master list
		//cscaDemo.createMasterList2();
		
		cscaDemo.createMasterList3();
	}
	
	public static void runCVCADemo() throws Exception {
		
		CVCADemo cvcaDemo = new CVCADemo();
		
		cvcaDemo.createCVCACert();
		
	}
}
