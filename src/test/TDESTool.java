package test;

import java.util.Map;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class TDESTool {
	
	public static void main(String[] args) throws Exception {
		
		
		String   key = "123456781234567812345678";  //3DES的KEY
		String   connect = "|0100|2120||15022089176|||全球通|石家庄|00|成功|2396";//需要加密的内容
		
		byte[]   enbyte  = tEncrypt3DES(key.getBytes(),padding(connect).getBytes());
		
		String temppass = Bytes2HexString(enbyte);
		
		System.out.println("加密后内容："+temppass);
		
		byte[]   dbyte = tdecrypt3des(key.getBytes(),enbyte);
		String dconnect =new String(removePadding(dbyte));
		System.out.println("解密后内容："+dconnect);
		
	}
	
	public static String CheckMAC(Map in) throws Exception {
		
		String key = getkeybychannelid(in);
		String packstr = (String) in.get("allpacketstr");
		
		String arg[] = packstr.split("\\|");
		
		String exchangetype = arg[0];
		String newpackstr = "";
		String oldmacstr = "";
		
		if(exchangetype.equals("0100")){
			
			newpackstr = arg[0] + "|" + arg[1] + "|" + arg[2] + "|" + arg[3] + "|" + arg[4] + "|" + arg[5] + "|" + arg[6] + "|" + arg[7] ;
			oldmacstr = arg[8];
			
		}else if(exchangetype.equals("0200")){

			newpackstr = arg[0] + "|" + arg[1] + "|" + arg[2] + "|" + arg[3] + "|" + arg[4] + "|" + arg[5] + "|" + arg[6] + "|" + arg[7] + "|" + arg[8] + "|" + arg[9] + "|" + arg[10] + "|" + arg[11] + "|" + arg[12] ;
			oldmacstr = arg[13];
			
		}else if(exchangetype.equals("0300")){

			newpackstr = arg[0] + "|" + arg[1] + "|" + arg[2] + "|" + arg[3] + "|" + arg[4] + "|" + arg[5] + "|" + arg[6] + "|" + arg[7] ;
			oldmacstr = arg[8];
			
		}else if(exchangetype.equals("0600")){

			newpackstr = arg[0] + "|" + arg[1] + "|" + arg[2] + "|" + arg[3] + "|" + arg[4] + "|" + arg[5] + "|" + arg[6] + "|" + arg[7] ;
			oldmacstr = arg[8];
			
		}else if(exchangetype.equals("0700")){

			newpackstr = arg[0] + "|" + arg[1] + "|" + arg[2] + "|" + arg[3] + "|" + arg[4] + "|" + arg[5] + "|" + arg[6] + "|" + arg[7] ;
			oldmacstr = arg[8];
		}else{
			
			throw new Exception("交易类型不正确");
		}
		
		String connect1 = Bytes2HexString(tCountMACx9_9(key.getBytes(),newpackstr.getBytes(),0,key.length()));
		
		if(!oldmacstr.equals(connect1)){
			
			throw new Exception("MAC校验失败");
		}
		
		return key;
	}
	
	private static String getkeybychannelid(Map in) throws Exception {

		String ChannelID = (String) in.get("ChannelID"); //渠道ID
		String ChannelPWD = (String) in.get("ChannelPWD");//渠道密码 
		
		if(ChannelID.equals("ecardtong")){
			
			if(!ChannelPWD.equals("card009")){
				throw new Exception("渠道信息不正确");
			}
			return "A1075646B1F98BC42A22659D";
		}
		
		return "未知的渠道ID";
	}

	public static String getdecodebykey(String con,String key) throws Exception {
		byte[] dbyte = tdecrypt3des(key.getBytes(),hexStringToBytes(con));
		String dconnect =new String(removePadding(dbyte));
		return dconnect;
	}

	public static byte[] tEncrypt3DES(byte[] tkey,byte[] tdata) throws Exception{

		SecretKey deskey = new SecretKeySpec(tkey, "DESede");//这里放入密码
		Cipher cipher = null;

		cipher = Cipher.getInstance("DESede/ecb/NoPadding");//ecb模式 不补位
		   
		cipher.init(Cipher.ENCRYPT_MODE,deskey);
		
		byte[] crypt_text = cipher.doFinal(tdata);//tem被加密byte

		return crypt_text;
	}
	//3des解密算法

	public static byte[] tdecrypt3des(byte[] key,byte[] src) throws Exception{
		
		SecretKey deskey = new SecretKeySpec(key, "DESede");//这里放入密码
		Cipher cipher = null;

		cipher = Cipher.getInstance("DESede/ecb/NoPadding");//ecb模式 不补位（  还是bcb模式需问清楚是那种）
			
		cipher.init(Cipher.DECRYPT_MODE,deskey);
		
		byte[] crypt_text = cipher.doFinal(src);

		return crypt_text;
		
		
	}
	public static byte[] hexStringToBytes(String hexString) {
		if (hexString == null || hexString.equals("")) {
			return null;
		}
		hexString = hexString.toUpperCase();
		int length = hexString.length() / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] d = new byte[length];
		for (int i = 0; i < length; i++) {
			int pos = i * 2;
			d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
		}
		return d;
	}
	 public static String Bytes2HexString(byte[] b) {
	     String ret = "";
	     for (int i = 0; i < b.length; i++) {
	       String hex = Integer.toHexString(b[i] & 0xFF);
	       if (hex.length() == 1) {
	         hex = '0' + hex;
	       }
	       ret += hex.toUpperCase();
	     }
	     return ret;
	   }
/**
 * 银联MAC算法ANSI-X9.9 
 * @param tKey
 * @param tBuffer
 * @param iOffset
 * @param iLength
 * @return
 * @throws Exception
 */
	 public static byte[] tCountMACx9_9(byte[] tKey, byte[] tBuffer, int iOffset, int iLength) throws Exception
		{
			byte[]	tResult = null;
			Vector	vctBlk = new Vector();
			byte[]	tTmp, tBlk, tXor, tDes;
			int	iNum, iLen, iPos, iN, i, j;
			
			if (tKey == null || tBuffer == null) return tResult;
			
			if (iOffset < 0) iOffset = 0;
			if (iLength < 0) iLength = tBuffer.length - iOffset;
			
			// 拆分数据（8字节块/Block）
			iLen = 0;
			iPos = iOffset;
			while (iLen < iLength && iPos < tBuffer.length)
			{
				tBlk = new byte[8];
				for (i = 0; i < tBlk.length; i ++) tBlk[i] = (byte)0;	// clear(0x00)
				for (i = 0; i < tBlk.length && iLen < iLength && iPos < tBuffer.length; i ++)
				{
					tBlk[i] = tBuffer[iPos++];
					iLen ++;
				}
				vctBlk.addElement(tBlk);	// store (back)
			}
			
			// 循环计算（XOR + DES）
			tDes = new byte[8];			// 初始数据
			for (i = 0; i < tDes.length; i ++) tDes[i] = (byte)0;	// clear(0x00)
			
			iNum = vctBlk.size();
			for (iN = 0; iN < iNum; iN ++)
			{
				tBlk = (byte[])vctBlk.elementAt(iN);
				if (tBlk == null) continue;
				
				tXor = new byte[Math.min(tDes.length,tBlk.length)];
				for (i = 0; i < tXor.length; i ++) tXor[i] = (byte)(tDes[i] ^ tBlk[i]);		// 异或(Xor)
				
				tTmp = tEncrypt3DES(tKey,tXor);	// DES加密
				
				for (i = 0; i < tDes.length; i ++) tDes[i] = (byte)0;				// clear
				for (i = 0; i < Math.min(tDes.length,tTmp.length); i ++) tDes[i] = tTmp[i];	// copy / transfer
				//System.out.println("block"+(iN+1)+":"+Bytes2HexString(tDes));
			}
			
			vctBlk.removeAllElements();		// clear
			
			tResult = tDes;
			
			return tResult;
		}
	 
	  public static String padding(String str) 
      {  
        byte[] oldByteArray; 
        try 
        {  
            oldByteArray = str.getBytes("UTF-8");  
            int numberToPad = 8 - oldByteArray.length % 8;  
            byte[] newByteArray = new byte[oldByteArray.length + numberToPad]; 
            System.arraycopy(oldByteArray, 0, newByteArray, 0, 
oldByteArray.length);  
            for (int i = oldByteArray.length; i < newByteArray.length; ++i) 
            {  
                newByteArray[i] = 0; 
            }  
            return new String(newByteArray, "UTF8"); 
        }  
        catch (Exception e) 
        {  
            System.out.println("Crypter.padding UnsupportedEncodingException");  
        }  
        return null; 
      }  
      public static byte[] removePadding(byte[] oldByteArray) 
      {  
        int numberPaded = 0;  
        for (int i = oldByteArray.length; i >= 0; --i) 
        {  
          if (oldByteArray[(i - 1)] != 0) 
          {  
            numberPaded = oldByteArray.length - i; 
            break; 
          } 
        } 
  
        byte[] newByteArray = new byte[oldByteArray.length - numberPaded];  
        System.arraycopy(oldByteArray, 0, 
newByteArray, 
0, newByteArray.length); 
  
        return newByteArray; 
      } 

		
	private static byte charToByte(char c) {
		return (byte) "0123456789ABCDEF".indexOf(c);
	}
}
