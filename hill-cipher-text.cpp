
#include<bits/stdc++.h>
using namespace std ;

vector<vector<int>> key ; // Global 


/***********************************************************************/
/* Functions used to calculate determinant */
/***********************************************************************/

int mod26(int x)
{
	return x >= 0 ? (x%26) : 26-(abs(x)%26) ;
}

vector<vector<int>> getCofactor(vector<vector<int>> mat, int p, int q, int n)
{
    int i = 0, j = 0;
 	vector<vector<int>> temp((mat.size()-1),vector<int>(mat.size()-1));

    // Looping for each element of the matrix
    for (int row = 0; row < n; row++)
    {
        for (int col = 0; col < n; col++)
        {
            //  Copying into temporary matrix only those
            //  element which are not in given row and
            //  column
            if (row != p && col != q)
            {
                temp[i][j++] = mat[row][col];
 
                // Row is filled, so increase row index and
                // reset col index
                if (j == n - 1)
                {
                    j = 0;
                    i++;
                }
            }
        }
    }
	return temp;
}
/* Recursive function for finding determinant of matrix.
n is current dimension of mat[][]. */
int determinantOfMatrix(vector<vector<int>> mat, int n)
{
	int D = 0; // Initialize result

	// Base case : if matrix contains single element
	if (n == 1)
		return mat[0][0];
	vector<vector<int>> Temp((mat.size()-1),vector<int>(mat.size()-1));

	int sign = 1; // To store sign multiplier

	// Iterate for each element of first row
	for (int f = 0; f < n; f++)
	{
		// Getting Cofactor of mat[0][f]
	Temp=getCofactor(mat, 0, f, n);
		D += sign * mat[0][f]* determinantOfMatrix(Temp, n - 1);

		// terms are to be added with alternate sign
		sign = -sign;
	}
	return mod26(D);
}
/***********************************************************************/


/***********************************************************************/
/* Functions used to Generate Key for the encryption */
/***********************************************************************/

void generatekey(int n)
{
	int det;
	do
	{
		key.clear();
	for(int i=0; i<n; i++) {
	        vector<int> v1;
	for(int j=0; j<n; j++) {
			v1.push_back(rand()%26+1);	//from 1-26
		} 
		key.push_back(v1);
	}
	det=determinantOfMatrix(key,n);
/*	
The keymatrix must satisfy the following conditions
1) Matrix should not be singular
2) Determinant must not have any common factors with modular base ( here =26)
*/
	}while(det==0 || det%2==0 || det%13==0 );
}

/***********************************************************************/


/***********************************************************************/
/* Functions to perform Matrix Operations 
Operations include calculations of 
1) Product of two matrices
2) Adjoint of a matrix
3) Inverse of a Matrix

Helper Function : 
findDetInverse(int R,int D=26 ): optimize the determinant of the inverse as per requirement

/***********************************************************************/

int findDetInverse(int R , int D = 26) // R is the remainder or determinant
{
   int i = 0 ;
   int p[100] = {0,1};
   int q[100] = {0} ; // quotient

   while(R!=0)
   {
      q[i] = D/R ;
      int oldD = D ;
      D = R ;
      R = oldD%R ;
      if(i>1)
      {
         p[i] = mod26(p[i-2] - p[i-1]*q[i-2]) ;
      }
      i++ ;
   }
   if (i == 1) return 1;
   else return p[i] = mod26(p[i-2] - p[i-1]*q[i-2]) ;
}

vector<vector<int>> multiplyMatrices(vector<vector<int>> a , int a_rows , int a_cols , vector<vector<int>> b, int b_rows , int b_cols)
{
	vector<vector<int>> res(a_rows,vector<int>(b_cols));
	for(int i=0 ; i < a_rows ; i++)
   {
      for(int j=0 ; j < b_cols ; j++)
      {
         for(int k=0 ; k < b_rows ; k++)
         {
            res[i][j] += a[i][k]*b[k][j] ;
         }
         res[i][j] = mod26(res[i][j]) ;
      }
   }
   return res;
}


// Function to get adjoint of A[N][N] in adj[N][N].
vector<vector<int>> adjoint(vector<vector<int>> A,int n)
{
	vector<vector<int>> adj(n,vector<int>(n));

	if (n == 1)
	{
		adj[0][0] = 1;
		return adj;
	}

	// temp is used to store cofactors of A[][]
	int sign = 1;
	vector<vector<int>> temp(n,vector<int>(n));

	for (int i=0; i<n; i++)
	{
		for (int j=0; j<n; j++)
		{
			// Get cofactor of A[i][j]
			temp=getCofactor(A, i, j, n);

			// sign of adj[j][i] positive if sum of row
			// and column indexes is even.
			sign = ((i+j)%2==0)? 1: -1;

			// Interchanging rows and columns to get the
			// transpose of the cofactor matrix
			adj[j][i] = (sign)*(determinantOfMatrix(temp, n-1));
		}
	}
	return adj;
}

// Function to calculate inverse

vector<vector<int>> inverse(vector<vector<int>> A,int n)
{
	// Find determinant of A[][]
	vector<vector<int>> inv(n,vector<int>(n));
	int det=determinantOfMatrix(A,n);
	int detInverse=findDetInverse(det);

	vector<vector<int>> adj(n,vector<int>(n));
	adj=adjoint(A, n);
	
	// Find Inverse using formula "inverse(A) = adj(A)/det(A)"
	for(int i=0; i<n ; i++)
   {
      for(int j=0; j<n ; j++)
      {
         inv[i][j] = mod26(adj[i][j] * detInverse) ;
      }
   }
	return inv;
}
/***********************************************************************/


/***********************************************************************/
/* Encryption Function
CipherText = Plain text * Key Matrix */
/***********************************************************************/

string encrypt(string pt, int n)
{
	int ptIter = 0  ;

	int row = (pt.length())/n; // number of rows in P
	vector<vector<int>> P(row,vector<int>(n)); // Plain Text

	/*Convert plain text to respective integers matrix*/
	for(int i=0; i<row ; i++)
	{
		for(int j=0; j<n; j++)
		{
			P[i][j] = pt[ptIter++]-'a' ;
		}
	}

	vector<vector<int>> C;	//Cipher Text
	// multiplyMatrices(mat_a , row_a , col_a ,mat_b,  row_b, col_b)
	C=multiplyMatrices(P, row , n, key,n , n);

	string ct = "" ;
	for(int i=0 ; i<row ; i++)
	{
		for(int j=0 ; j<n ;j++)
		{
			ct += (C[i][j] + 'a');
		}
	}
	return ct ;
}

/***********************************************************************/


/***********************************************************************/
/* Decryption Function
	Plain Text = Cipher Text * Inverse_Key 	*/
/***********************************************************************/

string decrypt(string ct, int n)
{
	int ctIter = 0 ;

	int row = ct.length()/n; // number of rows in C
	vector<vector<int>> C (row,vector<int>(n)); // Cipher Text

	for(int i=0; i<row ; i++)
	{
		for(int j=0; j<n; j++)
		{
			C[i][j] = ct[ctIter++]-'a' ;
		}
	}

	vector<vector<int>> P ;	//Plane Text


	vector<vector<int>> inv (n,vector<int>(n)); // Cipher Text
	inv=inverse(key, n);
   /* multiplyMatrices(mat_a , row_a , col_a , mat_b, row_b, col_b) */
	P=multiplyMatrices(C, row , n, inv,n , n) ;
	string pt = "" ;
	for(int i = 0 ; i<row ; i++)
	{
		for(int j=0 ; j<n ; j++)
		{
			pt += (P[i][j] + 'a');
		}
	}
	return pt ;
}
/***********************************************************************/


/***********************************************************************/
/* Main Function */
/***********************************************************************/

int main(void)
{
	string pt ;
	cout << "Enter the text to be encrypted : " ;
	getline(cin,pt);
	cout<<pt;
	/*Calculate the order of the key matrix such that 
	no extra element is left after making groups*/
	int n=2;
	for (int i = 2; i < 10; ++i)
	{
		if(pt.length()%i==0)
		{
			n=i;
			break;
		}
	}
	/*Generates a random Key of order n to be used for encryption*/
	generatekey(n);
	cout<<"\n\nThe Key matrix used is :\n";
	for(int i=0; i<n; i++) {
		for(int j=0; j<n; j++) {
			cout<<key[i][j]<<' ';
		}
		cout<<'\n';
	}
	cout<<'\n';

	cout << "\nOriginal text  : " << pt << endl;

	string ct = encrypt(pt, n) ;
	cout << "Encrypted text : " << ct << endl;

	string dt = decrypt(ct, n);
	cout << "Decrypted text : " << dt << endl;
	return 0;
}

/***********************************************************************/

/******************* OUTPUT-1 ****************************
Enter the text to be encrypted    : meetmenow
Enter order of key matrix : 2
Enter key matrix:
9   4
5   71
Original text  : meetmenow
Encrypted text : yybtyyfubp
Decrypted text : meetmenowx
************************************************************/

/****************** OUTPUT-2 ****************************
Enter the text to be encrypted    : paymoremoney
Enter order of key matrix : 3
Enter key matrix:
17   17   5
21   18   21
2    2    19
Original text  : paymoremoney
Encrypted text : rrlmwbkaspdh
Decrypted text : paymoremoney
************************************************************/

/******************* OUTPUT-3 ****************************
Enter the text to be encrypted    : attackistonight
Enter order of key matrix : 3
Enter key matrix:
3    10   20
20   9    17
9    4    17
Original text  : attackistonight
Encrypted text : fnwagwjgjkdnrrq
Decrypted text : attackistonight
************************************************************/

/******************* OUTPUT-4 ****************************
Enter the text to be encrypted    : hillciphertechnique
Enter order of key matrix : 2
Enter key matrix:
3   3
2   5
Original text  : hillciphertechnique
Encrypted text : ljdkwuhcutnzupdbksgx
Decrypted text : hillciphertechniquex
************************************************************/