using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class AES : CryptographicTechnique
    {
        byte[,] The_SBox = new byte[16, 16]
       {
      {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
      {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
      {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
      {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
      {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
      {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
      {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
      {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
      {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
      {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
      {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
      {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
      {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
      {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
      {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
      {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
       };

        byte[,] The_Rcon_matriex = new byte[4, 10]
        {
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
        };


        private byte[,] inverseThe_SBox = new byte[16, 16]
        {
      {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
      {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
      {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
      {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
      {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
      {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
      {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
      {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
      {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
      {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
      {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
      {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
      {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
      {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
      {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
      {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
        };

        public static void Fun_to_swap<var_0>(ref var_0 tempp_1, ref var_0 tempp_2)
        {
            var_0 variable_1;
            variable_1 = tempp_1;
            tempp_1 = tempp_2;
            tempp_2 = variable_1;
        }
        public static byte[,] inverseFun_Shift_Rows(byte[,] temp)
        {
            Fun_to_swap(ref temp[1, 2], ref temp[1, 3]);
            Fun_to_swap(ref temp[1, 1], ref temp[1, 2]);
            Fun_to_swap(ref temp[1, 0], ref temp[1, 1]);

            Fun_to_swap(ref temp[2, 0], ref temp[2, 2]);
            Fun_to_swap(ref temp[2, 1], ref temp[2, 3]);

            Fun_to_swap(ref temp[3, 0], ref temp[3, 1]);
            Fun_to_swap(ref temp[3, 1], ref temp[3, 2]);
            Fun_to_swap(ref temp[3, 2], ref temp[3, 3]);


            byte[,] The_Returned_value;
            The_Returned_value = temp;
            return The_Returned_value;
        }

        static byte[] Matriex_muliply(byte Item)
        {
            byte[] index;
            index = new byte[8];
            index[0] = Item;
            index[1] = Item >= 128 ? byte.Parse(((byte)(Item << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(Item << 1)).ToString());
            index[2] = index[1] >= 128 ? byte.Parse(((byte)(index[1] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[1] << 1)).ToString());
            index[3] = index[2] >= 128 ? byte.Parse(((byte)(index[2] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[2] << 1)).ToString());
            index[4] = index[3] >= 128 ? byte.Parse(((byte)(index[3] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[3] << 1)).ToString());
            index[5] = index[4] >= 128 ? byte.Parse(((byte)(index[4] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[4] << 1)).ToString());
            index[6] = index[5] >= 128 ? byte.Parse(((byte)(index[5] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[5] << 1)).ToString());
            index[7] = index[6] >= 128 ? byte.Parse(((byte)(index[6] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[6] << 1)).ToString());
            byte[] The_Returned_value;
            The_Returned_value = index;
            return The_Returned_value;

        }
        static byte[,] inverseMixCols(byte[,] state)
        {
            byte[,] INVMix = new byte[4, 4] {
                {0X0E,0X0B, 0X0D,0X09},
                { 0X09,0X0E,0X0B,0X0D},
                { 0X0D,0X09,0X0E,0X0B},
                { 0X0B,0X0D,0X09,0X0E}
        };

            // BitArray bits = new BitArray(BitConverter.GetBytes(second).ToArray());

            byte[,] The_New_Matriex = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte R = 0x00;

                    for (int q = 0; q < 4; q++)
                    {
                        byte tmp;
                        tmp = 0x00;
                        byte[] The_Byte_0 = new byte[8];
                        The_Byte_0 = Matriex_muliply(state[q, j]);
                        byte t = INVMix[i, q];
                        BitArray bitarray = new BitArray(BitConverter.GetBytes(t).ToArray());



                        for (int k = 0; k < 8; k++)
                        {

                            if (bitarray[k])
                            {
                                tmp = (byte)((int)tmp ^ (int)The_Byte_0[k]);
                            }
                        }

                        R = (byte)((int)R ^ (int)tmp);

                    }

                    The_New_Matriex[i, j] = R;

                }

            }

            byte[,] The_Returned_value;
            The_Returned_value = The_New_Matriex;
            return The_Returned_value;

        }

        private byte[,] inverseSubByte(byte[,] The_plaain_text)
        {
            byte[,] The_New_state;
            The_New_state = new byte[4, 4];
            byte[,] bytes2 = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    The_New_state[i, j] = inverseThe_SBox[The_plaain_text[i, j] >> 4, The_plaain_text[i, j] & 0x0f];

                }
            }



            byte[,] The_Returned_value;
            The_Returned_value = The_New_state;
            return The_Returned_value;


        }


        // fahd
        byte[, ,] The_Keeys = new byte[10, 4, 4];
        byte[,] Fun_Bring_The_Key(int The_Round_Key)
        {

            byte[,] The_New_Matriex;
            The_New_Matriex = new byte[4, 4];

            for (int i = 0; i < 4; ++i)
            {
                int var_18;

                for (var_18 = 0; var_18 < 4; ++var_18)
                {
                    The_New_Matriex[i, var_18] = The_Keeys[The_Round_Key, i, var_18];// bageb al key bta3 kol round
                }
            }

            byte[,] The_Returned_value;
            The_Returned_value = The_New_Matriex;
            return The_Returned_value;

        }


        public override string Decrypt(string cipherText, string key)
        {
            byte[,] The_cipherText_Matriex;
            The_cipherText_Matriex = StringToMatrixOfBytes(cipherText);
            byte[,] The_Keey;
            The_Keey = StringToMatrixOfBytes(key);
            for (int ii = 0; ii < 10; ii++)//10 rounds
            {
                for (int j = 0; j < 4; j++)//size of plain text
                {


                    for (int var_3 = 0; var_3 < 4; ++var_3)
                    {
                        The_Keeys[ii, var_3, j] = The_Keey[var_3, j];//rbta kol matries so8yra bal matriex bta3ha
                    }
                }

                The_Keey = GenerateRoundKey(The_Keey, ii + 1);   //to generate next key of next round          
            }
            //round 10
            The_cipherText_Matriex = AddRoundkey(The_cipherText_Matriex, The_Keey);//generate key to next round

            int i = 9;
            //the Rounds from 1 to 9
            for (int iii = 9; iii >= 1; --iii)
            {
                The_Keey = Fun_Bring_The_Key(iii);
                The_cipherText_Matriex = inverseMixCols(AddRoundkey(inverseSubByte(inverseFun_Shift_Rows(The_cipherText_Matriex)), The_Keey));
            }
            //Round 0
            The_Keey = Fun_Bring_The_Key(0);
            // Inverse_The_Inverse= inverseFun_Shift_Rows(The_cipherText_Matriex); 


            The_cipherText_Matriex = AddRoundkey(inverseSubByte(inverseFun_Shift_Rows(The_cipherText_Matriex)), The_Keey);

            return MatrixOfBytesToString(The_cipherText_Matriex);

        }


        public override string Encrypt(string The_plain_Text, string key)
        {
            byte[,] plain_text = StringToMatrixOfBytes(The_plain_Text);
            byte[,] bK = StringToMatrixOfBytes(key);
            //Round 0
            plain_text = AddRoundkey(plain_text, bK);
            //Rounds 1 to 9
            for (int i = 1; i <= 9; i++)
            {
                bK = GenerateRoundKey(bK, i);
                plain_text = AddRoundkey(MixColumns(Fun_Shift_Rows(fun_Sub_Bytes(plain_text))), bK);
            }
            //Round 10 without mix col
            bK = GenerateRoundKey(bK, 10);
            plain_text = AddRoundkey(Fun_Shift_Rows(fun_Sub_Bytes(plain_text)), bK);

            return MatrixOfBytesToString(plain_text);
        }
        private byte[,] fun_Sub_Bytes(byte[,] The_plaain_text)
        {

            //-condition
            byte[,] The_New_Matrieex;
            The_New_Matrieex = new byte[4, 4];

            //0x01 0x09 
            //0001 1001
            //0000 1111
            //9

            for (int i = 0; i < 4; i++)
            {

                for (int j = 0; j < 4; j++)
                {
                    /*get the first number by shift*/
                    /*/*get the second number by anding with f to stay same*/

                    The_New_Matrieex[i, j] = The_SBox[The_plaain_text[i, j] >> 4, The_plaain_text[i, j] & 0x0f];

                }

            }

            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matrieex;
            return The_Retured_value;
        }

        private byte[,] Fun_Shift_Rows(byte[,] The_Plain_text)//bn3ml shift 3la 7sb al index bta3t alrow
        // awl row mfesh shift 
        //tany row shift 1
        //and so on.
        //100%
        {
            byte[,] The_New_Matrieex;
            The_New_Matrieex = new byte[4, 4];


            for (int i = 0; i < 4; i++)
            {
                int j = 0;

                for (j = 0; j < 4; j++)
                {
                    int summution;
                    summution = j + i;
                    if (summution < 4)
                    {
                        The_New_Matrieex[i, j] = The_Plain_text[i, summution];//new place

                    }
                    //aly ma3molohom shift
                    else
                    {
                        The_New_Matrieex[i, j] = The_Plain_text[i, summution - 4];//reach last return from begining

                    }


                }

            }


            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matrieex;
            return The_Retured_value;


        }

        byte[,] The_mix_matriex = new byte[4, 4] {
        {0x02,0x03,0x01,0x01},
        {0x01,0x02,0x03,0x01},
        {0x01,0x01,0x02,0x03},
        {0x03,0x01,0x01,0x02}};

        private byte[,] MixColumns(byte[,] b_PT)
        {
            byte[,] b = new byte[4, 4];
            int num = 4;
            for (int i = 0; i < num; i++)// 3 for loop bec multibly matriex
            {
                for (int j = 0; j < num; j++)
                {
                    byte r = 0x00;
                    for (int q = 0; q < num; q++)
                    {
                        byte t;
                        if (The_mix_matriex[i, q] == 0x03)
                        {//sub diagonal
                            t = (byte)(b_PT[q, j] << 1);//shift 
                            if ((byte)(b_PT[q, j] & 0x80) == 0x80)//lma bywsl LL a5r ylf w yrg3 tany
                            {
                                //followed by XOR, when reach 11111, do xor with 1b to avod 1 loss
                                t = (byte)((int)t ^ (int)(0x1b));//to begin from first
                            }
                            t = (byte)((int)t ^ (int)b_PT[q, j]);//xor of reslut xor n3 alrakam aly mf fy al diagonal 
                        }
                        else if (The_mix_matriex[i, q] == 0x02)//shift left by 1 xor to main diagonal
                        {//diagonal
                            t = (byte)(b_PT[q, j] << 1);
                            if ((byte)(b_PT[q, j] & 0x80) == 0x80)//check wslat l a5r al matries wla lw b3ml and law tl3 b 8 yb2a wsalt ll a5r
                            {
                                t = (byte)((int)t ^ (int)(0x1b));//xor eith 1b 34an tdman any mrar4 many data zay 1 in(111)
                            }
                        }
                        else
                        {
                            t = b_PT[q, j];//hlm kol wa7ed bal index bta3o 34an m4 fy diagonal
                        }
                        r = (byte)((int)r ^ (int)t);
                    }
                    b[i, j] = r;
                }
            }
            return b;
        }

        private byte[,] GenerateRoundKey(byte[,] The_Keey, int Round_of_key)
        {
            byte[,] The_New_Matriex = new byte[4, 4];
            //hna sh2lb awl cell m3 a5r cell. w 3ml subistute mn al sbox
            //shift down
            The_New_Matriex[0, 0] = The_SBox[The_Keey[1, 3] >> 4, The_Keey[1, 3] & 0x0f];
            The_New_Matriex[1, 0] = The_SBox[The_Keey[2, 3] >> 4, The_Keey[2, 3] & 0x0f];
            The_New_Matriex[2, 0] = The_SBox[The_Keey[3, 3] >> 4, The_Keey[3, 3] & 0x0f];
            The_New_Matriex[3, 0] = The_SBox[The_Keey[0, 3] >> 4, The_Keey[0, 3] & 0x0f];
            //XOR 
            //get the first col 
            for (int i = 0; i < 4; i++)
            {
                The_New_Matriex[i, 0] = (byte)((int)The_New_Matriex[i, 0] ^ (int)The_Rcon_matriex[i, Round_of_key - 1]); //(Round_of_key - 1)34an awl round  el matriex bat3o gahz
                The_New_Matriex[i, 0] = (byte)((int)The_New_Matriex[i, 0] ^ (int)The_Keey[i, 0]);
            }

            for (int i = 1; i < 4; i++)//3yz ygeb tany col romady
            //bya5od aly ablo XOR m3 col 1 (tany col) 
            {
                for (int j = 0; j < 4; j++)
                    // gab aly ablo   //gab nafs rakm al col bta3 el matries
                    The_New_Matriex[j, i] = (byte)((int)The_New_Matriex[j, i - 1] ^ (int)The_Keey[j, i]);
            }

            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matriex;
            return The_Retured_value;
        }

        private byte[,] AddRoundkey(byte[,] The_Plain_text, byte[,] The_Keey)
        {
            //take the output from mix colmn (prevois phase) and make XOR with L key bta3 L round dy
            byte[,] The_New_Matrieex = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    The_New_Matrieex[j, i] = (byte)((int)The_Plain_text[j, i] ^ (int)The_Keey[j, i]);
                }
            }
            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matrieex;
            return The_New_Matrieex;
        }

        private byte[,] StringToMatrixOfBytes(string HexStr)
        {//functin to generate bkey (key bta3t al round aly ana feha)
            string s = HexStr.Substring(2, HexStr.Length - 2);//kol element fy el matiex 4ayl 2 number
            byte[] T = Enumerable.Range(0, s.Length)
                             .Where(x => x % 2 == 0)// get 2 no
                             .Select(x => Convert.ToByte(s.Substring(x, 2), 16))
                             .ToArray();
            byte[,] b = new byte[4, 4];
            int count = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    b[j, i] = T[count];//convert 1d to 2d array
                    count++;
                }
            }
            return b;
        }
        private string MatrixOfBytesToString(byte[,] Mbytes)
        {
            byte[] bt = new byte[16];
            int count = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    bt[count] = Mbytes[j, i];//convert 2D to 1D
                    count++;//next cell (2)
                }
            }
            StringBuilder hex = new StringBuilder(bt.Length * 2);//bytb3tlo length of 1D multibly by 2 because each cell has 2 chars 
            foreach (byte b in bt)//fill al hexa bl 7roof 
                hex.AppendFormat("{0:x2}", b);// bt7ot kol 7rfen wra b3d 
            return "0x" + hex.ToString();
        }
    }
}