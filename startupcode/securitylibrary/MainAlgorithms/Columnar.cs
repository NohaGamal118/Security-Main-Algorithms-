using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int numberOfRows = 0;
            int numberOfColumns = 0;
            int counter = 0;
            cipherText = cipherText.ToLower();
            int check = 0;
            for (int i = 4; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    numberOfColumns = i;
                }
            }
            numberOfRows = plainText.Length / numberOfColumns;
            char[,] firstMatrix = new char[numberOfRows, numberOfColumns];
            char[,] secondMatrix = new char[numberOfRows, numberOfColumns];
            List<int> key = new List<int>(numberOfColumns);
            for (int i = 0; i < numberOfRows; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    if (counter < plainText.Length)
                        firstMatrix[i, j] = plainText[counter];
                    if (counter >= plainText.Length)
                    {
                        if (firstMatrix.Length > plainText.Length)
                            firstMatrix[i, j] = 'x';
                    }
                    counter++;
                }
            }

            counter = 0;
            for (int i = 0; i < numberOfColumns; i++)
            {
                for (int j = 0; j < numberOfRows; j++)
                {
                    if (counter == plainText.Length)
                        break;
                    secondMatrix[j, i] = cipherText[counter];
                    counter++;
                }
            }

            for (int i = 0; i < numberOfColumns; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    for (int l = 0; l < numberOfRows; l++)
                    {
                        if (firstMatrix[l, i] == secondMatrix[l, j])
                        {
                            check++;
                        }
                        if (check == numberOfRows)
                            key.Add(j + 1);
                    }
                    check = 0;
                }
            }
            if (key.Count == 0)
            {
                for (int i = 0; i < numberOfColumns + 2; i++)
                {
                    key.Add(0);
                }
            }
            return key;
        }
        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();//Convert the cipher chars to lower
            int cipherTextLength = cipherText.Length;//storing the cipher length
            List<char> cipherList = new List<char>(cipherText);//list to store the result and return it down
            double maxelement = -1;//var to find the max value
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] > maxelement)//find the max num in the key that refer to the number of the column
                    maxelement = key[i];
            }
            int numberOfColumns = (int)maxelement;//get the floor of the result
            int numberOfRows = (int)Math.Ceiling((double)cipherTextLength / maxelement);//Find the num of rows
            char[,] cipherTextMatrix = new char[numberOfRows, numberOfColumns];
            int emptySquaresInMatrix = (numberOfColumns * numberOfRows) - cipherTextLength;
            int columnNumber = 1;
            int index = 0;
            for (int i = 0; i < numberOfColumns; i++)
            {
                int columnTurn = key.IndexOf(columnNumber);
                for (int j = 0; j < numberOfRows; j++)
                {
                    if (j != numberOfRows - 1)//all steps in the loop except the final step
                    {
                        cipherTextMatrix[j, columnTurn] = cipherList[index];
                        ++index;
                    }
                    else if ((j == numberOfRows - 1) && !(((i + 1) + emptySquaresInMatrix) > numberOfColumns))//reach it at the final looop
                    {
                        cipherTextMatrix[j, columnTurn] = cipherList[index];
                        ++index;
                    }

                }
                ++columnNumber;
            }
            string plainText = "";
            //store the result at 1d string
            for (int i = 0; i < numberOfRows; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    plainText += cipherTextMatrix[i, j];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            List<char> listPT = new List<char>(plainText);
            int plainTextLength = plainText.Length;//store the size of the plain text
            double maxelement = -1;//store the column number
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] > maxelement)//get the max element in the key
                    maxelement = key[i];
            }
            int numberOfColumns = (int)maxelement;
            int numberOfRows = (int)Math.Ceiling((double)plainTextLength / maxelement);
            char[,] plainTextMatrix = new char[numberOfRows, numberOfColumns];
            // for X
            int emptySquaresInMatrix = (numberOfColumns * numberOfRows) - plainTextLength;
            //fill the empty with x
            for (int i = 0; i < emptySquaresInMatrix; i++)
            {
                listPT.Add('x');
            }
            int index = 0;
            //m4 me7tag 7aga
            for (int i = 0; i < numberOfRows; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    plainTextMatrix[i, j] = listPT[index];
                    ++index;
                }
            }
            string cipherText = string.Empty;
            int columnNumber = 1;
            while (maxelement != 0)
            {
                int columnTurn = key.IndexOf(columnNumber);
                ++columnNumber;
                for (int j = 0; j < numberOfRows; j++)
                {
                    cipherText += plainTextMatrix[j, columnTurn];
                }
                maxelement--;
            }
            return cipherText;
        }
    }
}
