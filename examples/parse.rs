fn main() {
    let tag_start = "<input";
    let attribute_name = "name=\"state\"";
    let value_start = "value=\"";

    let mut remaining = html;
    let mut found_value = None;

    while let Some(tag_start_index) = remaining.find(tag_start) {
        remaining = &remaining[tag_start_index..];

        if let Some(attribute_index) = remaining.find(attribute_name) {
            remaining = &remaining[attribute_index..];

            if let Some(value_start_index) = remaining.find(value_start) {
                remaining = &remaining[value_start_index + value_start.len()..];

                if let Some(value_end_index) = remaining.find("\"") {
                    let value = &remaining[..value_end_index];
                    found_value = Some(value);
                    break; // 找到目标后跳出循环
                }
            }
        }

        remaining = &remaining[tag_start.len()..];
    }

    if let Some(value) = found_value {
        println!("Value: {}", value);
    }
}

const html: &str = r#"
<!DOCTYPE html>
<html>
<head>    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    
    
    <meta name="robots" content="noindex, nofollow" />
    
    
    <link rel="stylesheet" href="https://cdn.auth0.com/ulp/react-components/1.75.5/css/main.cdn.min.css" />
    <style id="custom-styles-container">
      
        

body {
  background: #ffffff;
  font-family: ulp-font, -apple-system, BlinkMacSystemFont, Roboto, Helvetica, sans-serif;
}
.cb8b84e38 {
  background: #ffffff;
}
.c491ad4bf.c1b0fd04f {
  background: #D00E17;
}
.c491ad4bf.c0d31bf3e {
  background: #0A8852;
}
.c08709d93 {
  background-color: #10a37f;
  color: #ffffff;
}
.c08709d93 a,
.c08709d93 a:visited {
  color: #ffffff;
}
.c23329ebf {
  background-color: #0A8852;
}
.cb393dcca {
  background-color: #D00E17;
}
@supports (mask-image: url('/static/img/branding-generic/copy-icon.svg')) {
  @supports not (-ms-ime-align: auto) {
    .ccf254d7e.cdf0e5eff::before {
      background-color: #D00E17;
    }
  }
}
.input.ccb840dba {
  border-color: #D00E17;
}
.error-cloud {
  background-color: #D00E17;
}
.error-fatal {
  background-color: #D00E17;
}
.error-local {
  background-color: #D00E17;
}
#alert-trigger {
  background-color: #D00E17;
}
      
    </style>
    <style>
      /* By default, hide features for javascript-disabled browsing */
      /* We use !important to override any css with higher specificity */
      /* It is also overriden by the styles in <noscript> in the header file */
      .no-js {
        clip: rect(0 0 0 0);
        clip-path: inset(50%);
        height: 1px;
        overflow: hidden;
        position: absolute;
        white-space: nowrap;
        width: 1px;
      }
    </style>
    <noscript>
      <style>
        /* We use !important to override the default for js enabled */
        /* If the display should be other than block, it should be defined specifically here */
        .js-required { display: none !important; }
        .no-js {
          clip: auto;
          clip-path: none;
          height: auto;
          overflow: auto;
          position: static;
          white-space: normal;
          width: var(--prompt-width);
        }
      </style>
    </noscript>
    
<style>
    @font-face {
        font-family: "ColfaxAI";
        src: url(https://cdn.openai.com/API/fonts/ColfaxAIRegular.woff2) format("woff2"),
            url(https://cdn.openai.com/API/fonts/ColfaxAIRegular.woff) format("woff");
        font-weight: normal;
        font-style: normal;
    }

    @font-face {
        font-family: "ColfaxAI";
        src: url(https://cdn.openai.com/API/fonts/ColfaxAIRegularItalic.woff2) format("woff2"),
            url(https://cdn.openai.com/API/fonts/ColfaxAIRegularItalic.woff) format("woff");
        font-weight: normal;
        font-style: italic;
    }

    @font-face {
        font-family: "ColfaxAI";
        src: url(https://cdn.openai.com/API/fonts/ColfaxAIBold.woff2) format("woff2"),
            url(https://cdn.openai.com/API/fonts/ColfaxAIBold.woff) format("woff");
        font-weight: bold;
        font-style: normal;
    }

    @font-face {
        font-family: "ColfaxAI";
        src: url(https://cdn.openai.com/API/fonts/ColfaxAIBoldItalic.woff2) format("woff2"),
            url(https://cdn.openai.com/API/fonts/ColfaxAIBoldItalic.woff) format("woff");
        font-weight: bold;
        font-style: italic;
    }

    :root {
        --font-family: "ColfaxAI",-apple-system,BlinkMacSystemFont,Helvetica,sans-serif;
        --primary-color: #10a37f;
        --primary-color-no-override: #10a37f;
        --action-primary-color: #10a37f;
        --link-color: #10a37f;
        --input-box-shadow-depth: 1px;
        --page-background-color: #ffffff;
    }

    body {
        font-family: var(--font-family);
        background-color: var(--page-background-color);
    }

    .oai-wrapper {
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 100%;
    }

    .oai-header {
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 32px 0 0;
        flex: 0 0 auto;
    }
    .oai-header svg {
        width: 32px;
        height: 32px;
        fill: #202123;
    }

    .oai-footer {
        display: flex;
        align-items: center;
        justify-content: center;
        color: #6e6e80;
        padding: 12px 0 24px;
        flex: 0 0 auto;
    }
    .oai-footer a {
        color: var(--primary-color);
        margin: 0 10px;
    }

    ._widget-auto-layout main._widget {
        flex: 1 0 auto;
        min-height: 0;
    }

    main header > img:first-of-type {
        display: none;
    }
    main > section, main > section > div:first-child {
        box-shadow: none;
    }
    main header > h1 {
        font-weight: bold !important;
        font-size: 32px !important;
    }
    main a {
        font-weight: normal !important;
    }
    .ulp-alternate-action {
        text-align: center;
    }
    button[type="submit"] {
        font-family: var(--font-family);
    }

    

    
        main header > h1 {
            margin-bottom: 0 !important;
        }
    
    
        main header > h1 + div {
            display: none !important;
        }
    
    
    
        div:has(> form[data-provider]) {
            display: flex;
            flex-direction: column;
        }
        form[data-provider="google"] {
            order: -1;
        }
        form[data-provider] {
            margin-bottom: var(--spacing-1);
        }
    

</style>
</head>
<body class="_widget-auto-layout">
    <div class="oai-wrapper">
        <header class="oai-header">
            <svg viewBox="140 140 520 520" xmlns="http://www.w3.org/2000/svg"><path d="m617.24 354a126.36 126.36 0 0 0 -10.86-103.79 127.8 127.8 0 0 0 -137.65-61.32 126.36 126.36 0 0 0 -95.31-42.49 127.81 127.81 0 0 0 -121.92 88.49 126.4 126.4 0 0 0 -84.5 61.3 127.82 127.82 0 0 0 15.72 149.86 126.36 126.36 0 0 0 10.86 103.79 127.81 127.81 0 0 0 137.65 61.32 126.36 126.36 0 0 0 95.31 42.49 127.81 127.81 0 0 0 121.96-88.54 126.4 126.4 0 0 0 84.5-61.3 127.82 127.82 0 0 0 -15.76-149.81zm-190.66 266.49a94.79 94.79 0 0 1 -60.85-22c.77-.42 2.12-1.16 3-1.7l101-58.34a16.42 16.42 0 0 0 8.3-14.37v-142.39l42.69 24.65a1.52 1.52 0 0 1 .83 1.17v117.92a95.18 95.18 0 0 1 -94.97 95.06zm-204.24-87.23a94.74 94.74 0 0 1 -11.34-63.7c.75.45 2.06 1.25 3 1.79l101 58.34a16.44 16.44 0 0 0 16.59 0l123.31-71.2v49.3a1.53 1.53 0 0 1 -.61 1.31l-102.1 58.95a95.16 95.16 0 0 1 -129.85-34.79zm-26.57-220.49a94.71 94.71 0 0 1 49.48-41.68c0 .87-.05 2.41-.05 3.48v116.68a16.41 16.41 0 0 0 8.29 14.36l123.31 71.19-42.69 24.65a1.53 1.53 0 0 1 -1.44.13l-102.11-59a95.16 95.16 0 0 1 -34.79-129.81zm350.74 81.62-123.31-71.2 42.69-24.64a1.53 1.53 0 0 1 1.44-.13l102.11 58.95a95.08 95.08 0 0 1 -14.69 171.55c0-.88 0-2.42 0-3.49v-116.68a16.4 16.4 0 0 0 -8.24-14.36zm42.49-63.95c-.75-.46-2.06-1.25-3-1.79l-101-58.34a16.46 16.46 0 0 0 -16.59 0l-123.31 71.2v-49.3a1.53 1.53 0 0 1 .61-1.31l102.1-58.9a95.07 95.07 0 0 1 141.19 98.44zm-267.11 87.87-42.7-24.65a1.52 1.52 0 0 1 -.83-1.17v-117.92a95.07 95.07 0 0 1 155.9-73c-.77.42-2.11 1.16-3 1.7l-101 58.34a16.41 16.41 0 0 0 -8.3 14.36zm23.19-50 54.92-31.72 54.92 31.7v63.42l-54.92 31.7-54.92-31.7z"/></svg>
        </header><main class="_widget login-id">
  <section class="ca775d19e _prompt-box-outer c20fc64c7">
    <div class="c4209fc2d ce0449bc6">
      
    
      
    
      <div class="cf12edc27">
        <header class="c6f6f3748 cb3cf2f60">
          <div title="OpenAI" id="custom-prompt-logo" style="width: auto !important; height: 60px !important; position: static !important; margin: auto !important; padding: 0 !important; background-color: transparent !important; background-position: center !important; background-size: contain !important; background-repeat: no-repeat !important"></div>
        
          <img class="c41e1d961 ce5e08e7e" id="prompt-logo-center" src="https://openai.com/content/images/2019/05/openai-avatar.png" alt="OpenAI" />
        
          
            <h1 class="ce6e62a0a c7f8e3f9b">Welcome</h1>
          
        
          <div class="cfdfdef49 c35d477ce">
            <p class="c27bed2f2 c864e0c2d">Log in to OpenAI to continue to Apps Client.</p>
          </div>
        </header>
      
        <div class="ca920f895 ca8471e59">
          
        
          
            <div class="ce1af4c6a ca1203c69">
              <div class="cedacd3f9">
                
              
                <form method="POST" class="c210378a2 _form-login-id" data-form-primary="true">
                  <input type="hidden" name="state" value="hKFo2SA2V2g2eUF1VUVLRUNDbTJ5MGNtOHcxY1ZXUTkwNFdMTKFur3VuaXZlcnNhbC1sb2dpbqN0aWTZIFNubkVydlFjdDV0WUpZOXJtS294Z0pVbGhZLUtFcjdFo2NpZNkgVGRKSWNiZTE2V29USHROOTVueXl3aDVFNHlPbzZJdEc" />
                
                  
                
                  <div class="ce1af4c6a ca1203c69">
                    <div class="cedacd3f9">
                      
                    
                      
                        <div class="input-wrapper _input-wrapper">
                          <div class="ccf254d7e c86ee2179 text c49367bf9" data-action-text="" data-alternate-action-text="">
                            <label class="c8db587cf no-js ce86485cd c4daf1f57" for="username">
                              Email address
                            </label>
                          
                            <input class="input ca4b7f6ee c41431cc2" inputMode="email" name="username" id="username" type="text" value="" required autoComplete="username" autoCapitalize="none" spellCheck="false" autoFocus />
                          
                            <div class="c8db587cf js-required ce86485cd c4daf1f57" data-dynamic-label-for="username" aria-hidden="true">
                              Email address
                            </div>
                          </div>
                        
                          
                        </div>
                      
                    
                      
                    </div>
                  </div>
                
                  
                
                  <input class="hide" type="password" autoComplete="off" tabindex="-1" aria-hidden="true" />
                
                  <input type="hidden" id="js-available" name="js-available" value="false" />
                
                  <input type="hidden" id="webauthn-available" name="webauthn-available" value="false" />
                
                  <input type="hidden" id="is-brave" name="is-brave" value="false" />
                
                  <input type="hidden" id="webauthn-platform-available" name="webauthn-platform-available" value="false" />
                
                  <div class="cf772ffae">
                    
                      <button type="submit" name="action" value="default" class="c89f1057d c08709d93 cfdf7e7ce c948a708e _button-login-id" data-action-button-primary="true">Continue</button>
                    
                  </div>
                </form>
              </div>
            </div>
          
        
          
            <div class="ulp-alternate-action  _alternate-action __s16nu9">
              <p class="c27bed2f2 c864e0c2d c2292b410">Don&#39;t have an account?
                <a class="cea0519b1 cf0e47f86" href="/u/signup/identifier?state=hKFo2SA2V2g2eUF1VUVLRUNDbTJ5MGNtOHcxY1ZXUTkwNFdMTKFur3VuaXZlcnNhbC1sb2dpbqN0aWTZIFNubkVydlFjdDV0WUpZOXJtS294Z0pVbGhZLUtFcjdFo2NpZNkgVGRKSWNiZTE2V29USHROOTVueXl3aDVFNHlPbzZJdEc" aria-label="">Sign up</a>
              </p>
            </div>
          
        
          
            <div class="c47c8448a c0ae8e25b">
              <span>Or</span>
            </div>
          
        
          
        
          
            
          
            <div class="c10017d5e cc4f8cbc7">
              
                <form method="post" data-provider="windowslive" class="c23436cee c3a9dc8ac c44e36b81" data-form-secondary="true">
                  <input type="hidden" name="state" value="hKFo2SA2V2g2eUF1VUVLRUNDbTJ5MGNtOHcxY1ZXUTkwNFdMTKFur3VuaXZlcnNhbC1sb2dpbqN0aWTZIFNubkVydlFjdDV0WUpZOXJtS294Z0pVbGhZLUtFcjdFo2NpZNkgVGRKSWNiZTE2V29USHROOTVueXl3aDVFNHlPbzZJdEc" />
                
                  <input type="hidden" name="connection" value="windowslive" />
                
                  <button type="submit" class="cb748e84b c06a93f6e ccf68b7db" data-provider="windowslive" data-action-button-secondary="true">
                    
                      <span class="c200921a3 c6af18580" data-provider="windowslive"></span>
                    
                  
                    <span class="cf5a17d0a">Continue with Microsoft Account</span>
                  </button>
                </form>
              
                <form method="post" data-provider="google" class="c23436cee c3a9dc8ac ca5a8d128" data-form-secondary="true">
                  <input type="hidden" name="state" value="hKFo2SA2V2g2eUF1VUVLRUNDbTJ5MGNtOHcxY1ZXUTkwNFdMTKFur3VuaXZlcnNhbC1sb2dpbqN0aWTZIFNubkVydlFjdDV0WUpZOXJtS294Z0pVbGhZLUtFcjdFo2NpZNkgVGRKSWNiZTE2V29USHROOTVueXl3aDVFNHlPbzZJdEc" />
                
                  <input type="hidden" name="connection" value="google-oauth2" />
                
                  <button type="submit" class="cb748e84b c06a93f6e c32451f76" data-provider="google" data-action-button-secondary="true">
                    
                      <span class="c200921a3 c6af18580" data-provider="google"></span>
                    
                  
                    <span class="cf5a17d0a">Continue with Google</span>
                  </button>
                </form>
              
                <form method="post" data-provider="apple" class="c23436cee c3a9dc8ac c93bf39a2" data-form-secondary="true">
                  <input type="hidden" name="state" value="hKFo2SA2V2g2eUF1VUVLRUNDbTJ5MGNtOHcxY1ZXUTkwNFdMTKFur3VuaXZlcnNhbC1sb2dpbqN0aWTZIFNubkVydlFjdDV0WUpZOXJtS294Z0pVbGhZLUtFcjdFo2NpZNkgVGRKSWNiZTE2V29USHROOTVueXl3aDVFNHlPbzZJdEc" />
                
                  <input type="hidden" name="connection" value="apple" />
                
                  <button type="submit" class="cb748e84b c06a93f6e ce5fe6a59" data-provider="apple" data-action-button-secondary="true">
                    
                      <span class="c200921a3 c6af18580" data-provider="apple"></span>
                    
                  
                    <span class="cf5a17d0a">Continue with Apple</span>
                  </button>
                </form>
              
            </div>
          
        </div>
      </div>
    </div>
  
    
  </section>
</main>
</body>
</html>
"#;
