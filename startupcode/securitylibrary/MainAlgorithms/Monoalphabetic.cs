using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        { 
            cipherText = cipherText.ToLower();
            char[] arr = new char[26];// To Store the result KEY and return it at the end of the function
            bool[] ar = new bool[26];//boolean array to store the status of the char if it found in array or not
            bool[] aray = new bool[1000];//To check if the cipher is found or not
            for (int i = 0; i < plainText.Length; i++)//loop on the plain Text 
            {
                int ind = (int)plainText[i] - 'a';//To get the index of the char by subtract its ascci code from the start char a 
                arr[ind] = cipherText[i];//To store the index of the char in the array and store the cipher in it
                ar[ind] = true;//make the index visited 
                aray[cipherText[i]] = true;//make the cipher visited
            }
            for (int i = 0; i < 26; i++)// loop for the alphapete 
            {
                if (ar[i] == false)//check if the index is not visited
                {
                    for (int j = 0; j < 26; j++)//loop for all alpha
                    {
                        if (aray[(int)('a' + j)] != true)//break at the first not visited char and get its value
                        {
                            arr[i] = (char)(97 + j);
                            ar[i] = true;
                            aray[97 + j] = true;
                            break;
                        }
                    }
                }
            }
            // After all steps finally i have the key 
            string ret = String.Join("", arr);//To convert the char array to string that help me to print it and to return
            Console.WriteLine(arr);
            return ret;
        }

        public string Decrypt(string cipherText, string key)
        {
            string chars = "";//To Store the plain text in it and return it 
            cipherText = cipherText.ToLower();//To convert All Chars in cipher to lower
            for (int i = 0; i < cipherText.Length; i++)
            {
                int j = key.IndexOf(cipherText[i]) + 'a' ;//To get the ascci code of the cipertext[i] and add it to string
                chars+=(char)j;//adding to the string
                
            }
            return chars;
    
}

        public string Encrypt(string plainText, string key)
        {
            string ciph = "";//To store the cipher text and return it
            plainText = plainText.ToLower();//to convert the plain text to lower
            for (int i = 0; i < plainText.Length; i++)
            {
                int j = plainText[i] -'a';//di bt3rfni tarteb el7arf f el 7rof english 
                //ex : if plain is b so j must be 1 second char in english the assci code of b is 98 if i subtact the assci code of char 'a' i will get j
                //so j=1 //Tarteb el plain f english
                ciph +=(key[j]);//adding it to ciph
            }
            return ciph;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {
            string Freq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            string Alpha = "abcdefghijklmnopqrstuvwxyz";
            char[] arrAlpha = Alpha.ToCharArray();
            char[] arrcipher = cipher.ToLower().ToCharArray();
            int[] arrcountCH = new int[26];
            char[] Frequences = Freq.ToCharArray();
            char[] arraymaxValue = new char[26];
            char[] plaintext = new char[cipher.Length];
            int y = 0;
            for (char i = 'a'; i <= 'z'; i++)
            {
                int count = 0;



                for (int j = 0; j < cipher.Length; j++)
                {
                    if (i == arrcipher[j])
                    {
                        count++;
                    }
                }
                arrcountCH[y] = count;
                y++;
            }
            int INDEX;
            for (int k = 0; k < arrcountCH.Length; k++)
            {
                int Max = arrcountCH.Max();
                INDEX = arrcountCH.ToList().IndexOf(Max);
                arraymaxValue[k] = arrAlpha[INDEX];
                arrcountCH.SetValue(-1, INDEX);
                // arrcountCH[INDEX] = -1;
            }



            for (int j = 0; j < cipher.Length; j++)
            {
                if (arrcipher[j] == arraymaxValue[0])
                {
                    plaintext[j] += Frequences[0];
                }
                if (arrcipher[j] == arraymaxValue[1])
                {
                    plaintext[j] += Frequences[1];
                }
                if (arrcipher[j] == arraymaxValue[2])
                {
                    plaintext[j] += Frequences[2];
                }
                if (arrcipher[j] == arraymaxValue[3])
                {
                    plaintext[j] += Frequences[3];
                }
                if (arrcipher[j] == arraymaxValue[4])
                {
                    plaintext[j] += Frequences[4];
                }
                if (arrcipher[j] == arraymaxValue[5])
                {
                    plaintext[j] += Frequences[5];
                }
                if (arrcipher[j] == arraymaxValue[6])
                {
                    plaintext[j] += Frequences[6];
                }
                if (arrcipher[j] == arraymaxValue[7])
                {
                    plaintext[j] += Frequences[7];
                }
                if (arrcipher[j] == arraymaxValue[8])
                {
                    plaintext[j] += Frequences[8];
                }
                if (arrcipher[j] == arraymaxValue[9])
                {
                    plaintext[j] += Frequences[9];
                }
                if (arrcipher[j] == arraymaxValue[10])
                {
                    plaintext[j] += Frequences[10];
                }
                if (arrcipher[j] == arraymaxValue[11])
                {
                    plaintext[j] += Frequences[11];
                }
                if (arrcipher[j] == arraymaxValue[12])
                {
                    plaintext[j] += Frequences[12];
                }
                if (arrcipher[j] == arraymaxValue[13])
                {
                    plaintext[j] += Frequences[13];
                }
                if (arrcipher[j] == arraymaxValue[14])
                {
                    plaintext[j] += Frequences[14];
                }
                if (arrcipher[j] == arraymaxValue[15])
                {
                    plaintext[j] += Frequences[15];
                }
                if (arrcipher[j] == arraymaxValue[16])
                {
                    plaintext[j] += Frequences[16];
                }
                if (arrcipher[j] == arraymaxValue[17])
                {
                    plaintext[j] += Frequences[17];
                }
                if (arrcipher[j] == arraymaxValue[18])
                {
                    plaintext[j] += Frequences[18];
                }
                if (arrcipher[j] == arraymaxValue[19])
                {
                    plaintext[j] += Frequences[19];
                }
                if (arrcipher[j] == arraymaxValue[20])
                {
                    plaintext[j] += Frequences[20];
                }
                if (arrcipher[j] == arraymaxValue[21])
                {
                    plaintext[j] += Frequences[21];
                }
                if (arrcipher[j] == arraymaxValue[22])
                {
                    plaintext[j] += Frequences[22];
                }
                if (arrcipher[j] == arraymaxValue[23])
                {
                    plaintext[j] += Frequences[23];
                }
                if (arrcipher[j] == arraymaxValue[24])
                {
                    plaintext[j] += Frequences[24];
                }
                if (arrcipher[j] == arraymaxValue[25])
                {
                    plaintext[j] += Frequences[25];
                }
            }



            return new string(plaintext);



        }
    }
}
