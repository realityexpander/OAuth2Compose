package com.realityexpander.oauth2compose

import android.app.Activity
import android.app.Activity.RESULT_OK
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import coil.compose.SubcomposeAsyncImage
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.tasks.Task
import com.realityexpander.oauth2compose.ui.theme.OAuth2ComposeTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ClientSecretBasic
import net.openid.appauth.ResponseTypeValues
import net.openid.appauth.TokenRequest
import net.openid.appauth.TokenResponse
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

// For OpenID AppAuth
// Important: Needs to have SHA1 signature set in Google Console for the Android app
// https://console.cloud.google.com/apis/credentials/
// Generate SHA-1 on keystore & create `OAuth Client ID` for the App Package
// keytool -keystore OAuth2Compose.keystore -list -v
//
// For Google Sign In
// In the Google Console, you only need to have a `Web Application` Client ID (NOT `Android`!!!)

// Github dashboard:
// https://github.com/settings/applications/2144082

// Starter &  reference code:
// https://velmurugan-murugesan.medium.com/appauth-android-velmm-com-d52a4980a668
// https://github.com/LinusMuema/Clowning/blob/oauth2/presentation/src/main/AndroidManifest.xml
// https://developer.android.com/training/id-auth/authenticate?authuser=2
// https://stackoverflow.com/questions/55666987/how-to-implement-oauth2-authorization-on-android
// https://www.youtube.com/watch?v=2m6rbQk0OcE // for github

class MainActivity : ComponentActivity() {

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            OAuth2ComposeTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    LoginOAuth2()
                }
            }
        }
    }
}

@Composable
fun LoginOAuth2() {
    val context = LocalContext.current

    val scope = rememberCoroutineScope()
    var buttonLoginGoogleOpenIdAppAuthLabel by remember { mutableStateOf("Login") }
    var buttonLoginGoogleSignInLabel by remember { mutableStateOf("Login") }
    var buttonLoginGithubOpenIdAppAuthLabel by remember { mutableStateOf("Login") }
    var userImageUrl by remember { mutableStateOf<String?>(null) }
    var userFullName by remember { mutableStateOf<String?>(null) }
    var userEmail by remember { mutableStateOf<String?>(null) }
    var userId by remember { mutableStateOf<String?>(null) }
    var statusMessage by remember { mutableStateOf<String>("") }

    // Using OpenID AppAuth
    val openIdAppAuthService = remember { AuthorizationService(context) }
    val openIdAppAuthStateManager = remember { AuthStateManager.getInstance(context) }

    // Using Google Sign In
    val googleSignInClient = remember { getGoogleSignInClient(context) }

    fun updateUIForGoogleSignIn(account: GoogleSignInAccount?) {
        if (account != null) {
            userImageUrl = account.photoUrl?.toString()
            userFullName = account.displayName
            userEmail = account.email
            userId = account.id
        } else {
            userImageUrl = null
            userFullName = null
            userEmail = null
            userId = null
        }
    }

    fun updateUIForOpenIdAppAuth(
        imageUrl: String? = null,
        fullName: String? = null,
        email: String? = null,
        id: String? = null,
    ) {
        userImageUrl = imageUrl
        userFullName = fullName
        userEmail = email
        userId = id
    }

    fun addStatusMessage(message: String) {
        statusMessage = "$statusMessage\n➤$message"
    }

    fun loadGithubProfile(accessToken: String, tokenResponse: TokenResponse? = null) {
        scope.launch {
            getGitHubProfileInfo(
                accessToken,
                onSuccess = { imageUrl, fullName, email, id ->
                    updateUIForOpenIdAppAuth(
                        imageUrl = imageUrl,
                        fullName = fullName,
                        email = email,
                        id = id,
                    )
                },
                onFailure = { exception ->
                    addStatusMessage(
                        exception.localizedMessage?.toString() ?: "null"
                    )
                }
            )

            // Save the results of this to Local Storage for re-launch


            // authorization completed
            Log.d("res", tokenResponse?.accessToken ?: "null")
            addStatusMessage(
                "startForResult_Github_OpenIdAppAuth authorization_completed " +
                        "tokenResponse.accessToken:" +
                        (tokenResponse?.accessToken?.take(20).toString())
            )
        }
    }

    LaunchedEffect(key1 = true) {
        // Check if user is already logged in via OpenID AppAuth
        if (openIdAppAuthStateManager?.current?.isAuthorized == true) {

            // Google will have additionClaimsMap after re-launch and currently logged-in
            val additionalClaimsMap =
                openIdAppAuthStateManager.current.parsedIdToken?.additionalClaims
            additionalClaimsMap?.let {
                updateUIForOpenIdAppAuth(
                    imageUrl = additionalClaimsMap?.get("picture") as String?,
                    fullName = additionalClaimsMap?.get("name") as String?,
                    email = additionalClaimsMap?.get("email") as String?,
                    id = additionalClaimsMap?.get("id") as String? // note: id is missing when using AppAuth
                )
                buttonLoginGoogleOpenIdAppAuthLabel = "Logout"
            }

            // Github will NOT have additionalClaimsMap, but we still have the accessToken, so perform load here.
            // There is likely a better way to handle this, or it may just be handled on a case-by-case basis.
            additionalClaimsMap ?: run {
                val accessToken = openIdAppAuthStateManager.current.accessToken
                accessToken?.let {
                    loadGithubProfile(accessToken)
                    buttonLoginGithubOpenIdAppAuthLabel = "Logout"
                } ?: run {
                    addStatusMessage("isAuthorized && accessToken is null")
                }
            }


        }

        // Check if user is already logged in via GoogleSignIn Client
        googleSignInClient.silentSignIn().addOnCompleteListener { task ->
            if (task.isSuccessful) {
                // The signed in account is stored in the task's result.
                val googleAccount = task.result

                buttonLoginGoogleSignInLabel = "Logout"
                updateUIForGoogleSignIn(googleAccount)
            }
        }
    }

    // Note: Only for GoogleSignInClient
    fun handleSignInResult(task: Task<GoogleSignInAccount>) {
        try {
            // Signed in successfully, show authenticated UI results by showing signed-in user's info.
            val account: GoogleSignInAccount? = task.getResult(ApiException::class.java)

            addStatusMessage("id: " + account?.id)
            addStatusMessage("displayName: " + account?.displayName)
            addStatusMessage("serverAuthCode: " + account?.serverAuthCode)
            addStatusMessage("idToken: " + account?.idToken?.take(20))
            addStatusMessage("grantedScopes: " + account?.grantedScopes?.joinToString())
            addStatusMessage("requestedScopes: " + account?.requestedScopes?.joinToString())

            buttonLoginGoogleSignInLabel = "Logout"
            updateUIForGoogleSignIn(account)
        } catch (e: ApiException) {
            // The ApiException status code indicates the detailed failure reason.
            // Please refer to the GoogleSignInStatusCodes class reference for more information.
            Log.w("GoogleSignIn", "signInResult:failed code=" + e.statusCode)
            updateUIForGoogleSignIn(null)
            addStatusMessage("handleSignInResult: failed code=" + e.statusCode.toString())
        }
    }


    //---------------
    // Google OpenId AppAuth Client Sign in to Google
    val startForResult_Google_OpenIdAppAuth =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result: ActivityResult ->
            if (result.resultCode == RESULT_OK) {
                val response = AuthorizationResponse.fromIntent(result.data!!)
                val exception = AuthorizationException.fromIntent(result.data)

                response ?: run {
                    Log.d("response", "null")
                    addStatusMessage("startForResult_OpenIdAppAuth exception: ${exception?.message}")
                    return@rememberLauncherForActivityResult
                }

                openIdAppAuthStateManager?.updateAfterAuthorization(response, exception)

                openIdAppAuthService.performTokenRequest(
                    response.createTokenExchangeRequest()
                ) { tokenResponse, authorizationException ->

                    tokenResponse ?: run {
                        Log.d("tokenResponse", "null")
                        addStatusMessage("startForResult_Google_OpenIdAppAuth authorizationException.ex: " + authorizationException?.message)
                        return@performTokenRequest
                    }

                    openIdAppAuthStateManager?.updateAfterTokenResponse(
                        tokenResponse,
                        authorizationException
                    )
                    buttonLoginGoogleOpenIdAppAuthLabel = "Logout"

                    Log.d("accessToken", tokenResponse.accessToken.toString())
                    addStatusMessage(
                        "startForResult_OpenIdAppAuth tokenResponse.accessToken:" +
                                (tokenResponse.accessToken?.take(20).toString())
                    )

                    tokenResponse.accessToken?.let { token ->
                        scope.launch {
                            getGoogleProfileInfo(
                                token,
                                onSuccess = { imageUrl, fullName, email, id ->
                                    updateUIForOpenIdAppAuth(
                                        imageUrl = imageUrl,
                                        fullName = fullName,
                                        email = email,
                                        id = id,
                                    )
                                },
                                onFailure = { exception ->
                                    addStatusMessage(
                                        exception.localizedMessage?.toString() ?: "null"
                                    )
                                }
                            )

                            // authorization completed
                            Log.d("res", tokenResponse.accessToken ?: "null")
                            addStatusMessage(
                                "startForResult_Google_OpenIdAppAuth authorization_completed " +
                                        "tokenResponse.accessToken:" +
                                        (tokenResponse.accessToken?.take(20).toString())
                            )
                        }
                    }
                }
            }
        }

    val startForResult_Github_OpenIdAppAuth =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result: ActivityResult ->
            if (result.resultCode == RESULT_OK) {
                val response = AuthorizationResponse.fromIntent(result.data!!)
                val exception = AuthorizationException.fromIntent(result.data)

                exception?.run {
                    Log.d("response", "null")
                    addStatusMessage("startForResult_Github_OpenIdAppAuth exception: ${exception?.message}")
                    return@rememberLauncherForActivityResult
                }

                val secret = ClientSecretBasic(BuildConfig.GITHUB_CLIENT_SECRET)
                val tokenRequest = response?.createTokenExchangeRequest()

                openIdAppAuthStateManager?.updateAfterAuthorization(response, exception)

                openIdAppAuthService.performTokenRequest(
                    tokenRequest!!,
                    secret
                ) { tokenResponse, authorizationException ->

                    tokenResponse ?: run {
                        Log.d("tokenResponse", "null")
                        addStatusMessage("startForResult_Github_OpenIdAppAuth authorizationException.ex: " +
                                authorizationException?.message)
                        return@performTokenRequest
                    }

                    authorizationException?.run {
                        Log.d("authorizationException", authorizationException.localizedMessage ?: "Unknown error")
                        addStatusMessage("startForResult_Github_OpenIdAppAuth authorizationException.ex: " +
                                authorizationException.message)
                        return@performTokenRequest
                    }

                    openIdAppAuthStateManager?.updateAfterTokenResponse(
                        tokenResponse,
                        authorizationException
                    )
                    buttonLoginGithubOpenIdAppAuthLabel = "Logout"

                    Log.d("accessToken", tokenResponse.accessToken.toString())
                    addStatusMessage(
                        "startForResult_Github_OpenIdAppAuth tokenResponse.accessToken:" +
                                (tokenResponse.accessToken?.take(20).toString())
                    )

                    tokenResponse.accessToken?.let { accessToken ->
                        loadGithubProfile(accessToken, tokenResponse)
                    }
                }
            }
        }


    //---------------
    // GoogleSignInClient Sign in to Google
    val startForResult_GoogleSignInAccount =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result: ActivityResult ->
            result.data?.let { data ->
                addStatusMessage(
                    "googleSignInStatus error:" + (data.extras?.get("googleSignInStatus")
                        ?.toString() ?: "null")
                )
                // If you get DEVELOPER_ERROR, it means you ARE NOT using a `WEB Client ID` from the GCP console,
                // or the credential is malformed in some other way.
            }

            if (result.resultCode == Activity.RESULT_OK) {
                val intent = result.data
                if (intent != null) {
                    val task: Task<GoogleSignInAccount> =
                        GoogleSignIn.getSignedInAccountFromIntent(intent)
                    handleSignInResult(task)
                }
            }
            if (result.resultCode == Activity.RESULT_CANCELED) {
                updateUIForGoogleSignIn(null)
                addStatusMessage("RESULT_CANCELED")
            }
        }


    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {

        // • Google Sign In using GoogleSignInClient
        Button(
            onClick = {
                if (buttonLoginGoogleSignInLabel == "Logout") {
                    googleSignInClient.signOut()

                    updateUIForGoogleSignIn(null)
                    buttonLoginGoogleSignInLabel = "Login"
                    addStatusMessage("Logged out")
                    return@Button
                } else {
                    startForResult_GoogleSignInAccount.launch(googleSignInClient.signInIntent)
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
        ) {
            Text(text = "$buttonLoginGoogleSignInLabel to Google with GoogleSignInClient")
        }
        Spacer(modifier = Modifier.height(16.dp))


        // • Google OpenId AppAuth Sign In
        Button(
            enabled = !buttonLoginGithubOpenIdAppAuthLabel.startsWith("Logout"),
            onClick = {
                if (buttonLoginGoogleOpenIdAppAuthLabel == "Logout") {
                    openIdAppAuthStateManager?.replace(AuthState()) // performs logout
                    updateUIForOpenIdAppAuth(null, null, null, null)
                    buttonLoginGoogleOpenIdAppAuthLabel = "Login"
                    addStatusMessage("Logged out")
                    return@Button
                } else {
                    signInGoogleWithOpenIdAuthApp(openIdAppAuthService, startForResult_Google_OpenIdAppAuth)
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
        ) {
            Text(text = "$buttonLoginGoogleOpenIdAppAuthLabel to Google with OpenId AppAuth Library")
        }
        Spacer(modifier = Modifier.height(16.dp))

        // • Github OpenId AppAuth Sign In
        Button(
            enabled = !buttonLoginGoogleOpenIdAppAuthLabel.startsWith("Logout"),
            onClick = {
                if (buttonLoginGithubOpenIdAppAuthLabel == "Logout") {
                    openIdAppAuthStateManager?.replace(AuthState()) // performs logout
                    updateUIForOpenIdAppAuth(null, null, null, null)
                    buttonLoginGithubOpenIdAppAuthLabel = "Login"
                    addStatusMessage("Logged out")
                    return@Button
                } else {
                    signInGithubWithOpenIdAuthApp(openIdAppAuthService, startForResult_Github_OpenIdAppAuth)
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
        ) {
            Text(text = "$buttonLoginGithubOpenIdAppAuthLabel to Github with OpenId AppAuth Library")
        }
        Spacer(modifier = Modifier.height(16.dp))

        // • PHOTO IMAGE & ACCOUNT INFO
        userImageUrl?.let {
            SubcomposeAsyncImage(
                model = userImageUrl,
                contentDescription = "User Image",
                contentScale = ContentScale.FillWidth,
                loading = {
                    CircularProgressIndicator(
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .size(100.dp)
                            .align(Alignment.Center)
                            .padding(10.dp)
                    )
                },
                modifier = Modifier
                    .fillMaxWidth()
            )
        }
        userFullName?.let {
            Text(it)
        }
        userEmail?.let {
            Text(it)
        }
        userId?.let {
            Text(it)
        }

        Text(statusMessage)
    }

}


private fun getGoogleSignInClient(context: Context): GoogleSignInClient {
    val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
        // GOOGLE_CLIENT_ID
        // IMPORTANT! MUST be `Web Application` Google Client ID from the Google Cloud Console (APIs & Services)
        .requestIdToken(BuildConfig.GOOGLE_CLIENT_ID_WEB_APPLICATION)
        .requestEmail()
        .requestId()
        .requestProfile()
        .build()
    return GoogleSignIn.getClient(context, gso)
}


fun signInGoogleWithOpenIdAuthApp(
    authService: AuthorizationService,
    startForResult: ActivityResultLauncher<Intent>
) {
    val serviceConfig = AuthorizationServiceConfiguration(
        Uri.parse("https://accounts.google.com/o/oauth2/v2/auth"),
        Uri.parse("https://oauth2.googleapis.com/token")
    )

    // GOOGLE_CLIENT_ID  // IMPORTANT! MUST BE `Android` Google Client ID
    val clientId = BuildConfig.GOOGLE_CLIENT_ID_ANDROID
    //val redirectUri = Uri.parse("com.realityexpander.oauth2compose:/ooogaboooga.oo") // note: name of resource doesn't matter, just the scheme.
    val redirectUri = //BuildConfig.APPLICATION_ID +":/oauth2callback"
        Uri.parse("com.realityexpander.oauth2compose:/oauth2callback") // by convention, we name it something sensible.
    val builder = AuthorizationRequest.Builder(
        serviceConfig,
        clientId,
        ResponseTypeValues.CODE,
        redirectUri
    )
    builder.setScopes("profile email")
    val authRequest = builder.build()

    val intent = authService.getAuthorizationRequestIntent(authRequest)
    startForResult.launch(intent)
}

fun signInGithubWithOpenIdAuthApp(
    authService: AuthorizationService,
    startForResult: ActivityResultLauncher<Intent>
) {
    val serviceConfig = AuthorizationServiceConfiguration(
        Uri.parse("https://github.com/login/oauth/authorize"),
        Uri.parse("https://github.com/login/oauth/access_token")
    )

    // GITHUB_CLIENT_SECRET
    val clientId = BuildConfig.GITHUB_CLIENT_ID
    val redirectUri =
        Uri.parse("com.realityexpander.oauth2compose://oauth2callback") // NOTE: the double slashes here bc github doesn't allow single slashes...
    val builder = AuthorizationRequest.Builder(
        serviceConfig,
        clientId,
        ResponseTypeValues.CODE,
        redirectUri
    )
    builder.setScopes("user repo")
    val authRequest = builder.build()

    val intent = authService.getAuthorizationRequestIntent(authRequest)
    startForResult.launch(intent)
}

suspend fun getGoogleProfileInfo(
    accessToken: String,
    onSuccess: (
        imageUrl: String,
        fullName: String,
        email: String,
        id: String,
    ) -> Unit,
    onFailure: (exception: Exception) -> Unit = {}
) {
    withContext(Dispatchers.IO) {
        val client = OkHttpClient()
        val request = Request.Builder()
            .url("https://www.googleapis.com/oauth2/v3/userinfo")
            .addHeader("Authorization", "Bearer $accessToken")
            .build()
        try {
            val response = client.newCall(request).execute()
            val jsonBody: String = response.body!!.string()
            Log.i("LOG_TAG", "Google User Info Response $jsonBody")

            val userInfo = JSONObject(jsonBody)
            val fullName = userInfo.optString("name", null)
            val imageUrl = userInfo.optString("picture", null)
            val email = userInfo.optString("email", null)
            val id = userInfo.optString("sub", null)
            val emailVerified = userInfo.optString("email_verified", null)  // true/false
            val locale = userInfo.optString("locale", null) // en

            // For some reason, the `id` is not retained for next app launch log-in using AppAuth
            // Therefore, if using OpenId AppAuth, the `id` should the saved in App shared preferences.

            onSuccess(imageUrl, fullName, email, id)
        } catch (exception: Exception) {
            Log.w("LOG_TAG", exception)
            onFailure(exception)
        }
    }
}

suspend fun getGitHubProfileInfo(
    accessToken: String,
    onSuccess: (
        imageUrl: String,
        fullName: String,
        email: String,
        id: String,
    ) -> Unit,
    onFailure: (exception: Exception) -> Unit = {}
) {
    withContext(Dispatchers.IO) {
        val client = OkHttpClient()
        val request = Request.Builder()
            .url("https://api.github.com/user")
            .addHeader("Authorization", "token $accessToken")
            .build()
        try {
            val response = client.newCall(request).execute()
            val jsonBody: String = response.body!!.string()
            Log.i("LOG_TAG", "GitHub User Info Response $jsonBody")

            val userInfo = JSONObject(jsonBody)
            val fullName = userInfo.optString("name", null)
            val imageUrl = userInfo.optString("avatar_url", null)
            val email = userInfo.optString("email", null)
            val id = userInfo.optString("id", null)

            // For some reason, the `id` is not retained for next app launch log-in using AppAuth
            // Therefore, if using OpenId AppAuth, the `id` should the saved in App shared preferences.

            onSuccess(imageUrl, fullName, email, id)
        } catch (exception: Exception) {
            Log.w("LOG_TAG", exception)
            onFailure(exception)
        }
    }
}

data class GithubUserDto(
    val id: Int,
    val avatar_url: String,
    val followers: Int,
    val following: Int,
    val login: String,
    val owned_private_repos: Int,
    val private_gists: Int,
    val public_gists: Int,
    val public_repos: Int,
    val total_private_repos: Int,
)


























