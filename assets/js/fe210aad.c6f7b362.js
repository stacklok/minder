"use strict";(self.webpackChunkminder_docs=self.webpackChunkminder_docs||[]).push([[5201],{6509:(e,i,n)=>{n.r(i),n.d(i,{assets:()=>a,contentTitle:()=>s,default:()=>d,frontMatter:()=>o,metadata:()=>l,toc:()=>c});var t=n(74848),r=n(28453);const o={title:"Configure GitHub Provider",sidebar_position:20},s="Getting Started (Configuring a GitHub Provider)",l={id:"run_minder_server/config_oauth",title:"Configure GitHub Provider",description:"Minder currently only supports GitHub as a provider. Later versions will support other providers.",source:"@site/docs/run_minder_server/config_oauth.md",sourceDirName:"run_minder_server",slug:"/run_minder_server/config_oauth",permalink:"/run_minder_server/config_oauth",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:20,frontMatter:{title:"Configure GitHub Provider",sidebar_position:20},sidebar:"minder",previous:{title:"Run the Server",permalink:"/run_minder_server/run_the_server"},next:{title:"Helm Install",permalink:"/run_minder_server/installing_minder"}},a={},c=[{value:"Prerequisites",id:"prerequisites",level:2},{value:"Create a GitHub App (option 1)",id:"create-a-github-app-option-1",level:2},{value:"Configure the GitHub App",id:"configure-the-github-app",level:3},{value:"Set up <code>server-config.yaml</code>",id:"set-up-server-configyaml",level:3},{value:"Set up a fallback token for listing artifacts",id:"set-up-a-fallback-token-for-listing-artifacts",level:3},{value:"(optional) Configure the webhook",id:"optional-configure-the-webhook",level:3},{value:"Create a GitHub OAuth Application (option 2)",id:"create-a-github-oauth-application-option-2",level:2}];function h(e){const i={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",img:"img",li:"li",ol:"ol",p:"p",pre:"pre",ul:"ul",...(0,r.R)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(i.h1,{id:"getting-started-configuring-a-github-provider",children:"Getting Started (Configuring a GitHub Provider)"}),"\n",(0,t.jsx)(i.p,{children:"Minder currently only supports GitHub as a provider. Later versions will support other providers."}),"\n",(0,t.jsx)(i.p,{children:"Minder can either use GitHub OAuth2 application or GitHub App for authentication. This means that you will need to\nconfigure a GitHub OAuth 2.0 application or a GitHub App, to allow enrollment of users into Minder."}),"\n",(0,t.jsx)(i.h2,{id:"prerequisites",children:"Prerequisites"}),"\n",(0,t.jsxs)(i.ul,{children:["\n",(0,t.jsxs)(i.li,{children:[(0,t.jsx)(i.a,{href:"https://github.com",children:"GitHub"})," account"]}),"\n"]}),"\n",(0,t.jsx)(i.h2,{id:"create-a-github-app-option-1",children:"Create a GitHub App (option 1)"}),"\n",(0,t.jsx)(i.p,{children:"This approach allows users fine-grained control over the permissions that Minder has in their repositories. It also\nallows users to limit the repositories that Minder can access."}),"\n",(0,t.jsx)(i.h3,{id:"configure-the-github-app",children:"Configure the GitHub App"}),"\n",(0,t.jsxs)(i.ol,{children:["\n",(0,t.jsxs)(i.li,{children:["Navigate to ",(0,t.jsx)(i.a,{href:"https://github.com/settings/profile",children:"GitHub Developer Settings"})]}),"\n",(0,t.jsx)(i.li,{children:'Select "Developer Settings" from the left hand menu'}),"\n",(0,t.jsx)(i.li,{children:'Select "GitHub Apps" from the left hand menu'}),"\n",(0,t.jsx)(i.li,{children:'Select "New GitHub App"'}),"\n",(0,t.jsxs)(i.li,{children:["Enter the following details:","\n",(0,t.jsxs)(i.ul,{children:["\n",(0,t.jsxs)(i.li,{children:["GitHub App Name: ",(0,t.jsx)(i.code,{children:"My Minder App"})," (or any other name you like)"]}),"\n",(0,t.jsxs)(i.li,{children:["Homepage URL: ",(0,t.jsx)(i.code,{children:"http://localhost:8080"})]}),"\n",(0,t.jsxs)(i.li,{children:["Callback URL: ",(0,t.jsx)(i.code,{children:"http://localhost:8080/api/v1/auth/callback/github-app/app"})]}),"\n",(0,t.jsx)(i.li,{children:'Select the checkbox for "Request user authorization (OAuth) during installation"'}),"\n"]}),"\n"]}),"\n",(0,t.jsxs)(i.li,{children:["Select the following permissions:","\n",(0,t.jsxs)(i.ul,{children:["\n",(0,t.jsxs)(i.li,{children:["Repository Permissions:","\n",(0,t.jsxs)(i.ul,{children:["\n",(0,t.jsx)(i.li,{children:"Administration (read and write)"}),"\n",(0,t.jsx)(i.li,{children:"Contents (read and write)"}),"\n",(0,t.jsx)(i.li,{children:"Metadata (read only)"}),"\n",(0,t.jsx)(i.li,{children:"Packages (read and write)"}),"\n",(0,t.jsx)(i.li,{children:"Pull requests (read and write)"}),"\n",(0,t.jsx)(i.li,{children:"Repository security advisories (read and write)"}),"\n",(0,t.jsx)(i.li,{children:"Webhooks (read and write), Workflows (read and write)"}),"\n"]}),"\n"]}),"\n",(0,t.jsx)(i.li,{children:"Organization Permissions:"}),"\n",(0,t.jsx)(i.li,{children:"Members (read only)"}),"\n"]}),"\n"]}),"\n",(0,t.jsx)(i.li,{children:'(optional) For the option "Where can this GitHub App be installed?", select "Any account" if you want to allow any GitHub user to install the app. Otherwise, select "Only on this account" to restrict the app to only your account.'}),"\n",(0,t.jsx)(i.li,{children:'Select "Create GitHub App"'}),"\n",(0,t.jsx)(i.li,{children:"Generate a client secret"}),"\n",(0,t.jsx)(i.li,{children:"Generate a private key"}),"\n"]}),"\n",(0,t.jsxs)(i.h3,{id:"set-up-server-configyaml",children:["Set up ",(0,t.jsx)(i.code,{children:"server-config.yaml"})]}),"\n",(0,t.jsx)(i.p,{children:"The next step sets up Minder with the GitHub App you just created."}),"\n",(0,t.jsxs)(i.p,{children:["In your ",(0,t.jsx)(i.code,{children:"server-config.yaml"})," file add the following section:"]}),"\n",(0,t.jsx)(i.pre,{children:(0,t.jsx)(i.code,{className:"language-yaml",children:'github-app:\n  client_id: <client-id>\n  client_secret: <client-secret>\n  redirect_uri: "http://localhost:8080/api/v1/auth/callback/github-app/app" # This needs to match the registered callback URL in the GitHub App\n'})}),"\n",(0,t.jsxs)(i.p,{children:["Replace ",(0,t.jsx)(i.code,{children:"<client-id>"})," and ",(0,t.jsx)(i.code,{children:"<client-secret>"})," with the client ID and secret of your GitHub App."]}),"\n",(0,t.jsxs)(i.p,{children:["Then, add the following section to your ",(0,t.jsx)(i.code,{children:"server-config.yaml"})," file:"]}),"\n",(0,t.jsx)(i.pre,{children:(0,t.jsx)(i.code,{className:"language-yaml",children:'provider:\n  github-app:\n    app_name: <app-name>\n    app_id: <app-id>\n    user_id: <user-id>\n    private_key: ".secrets/github-app.pem"\n'})}),"\n",(0,t.jsxs)(i.p,{children:["Replace ",(0,t.jsx)(i.code,{children:"<app-name>"})," with the name of your app, which you can get by looking at the GitHub URL when editing your GitHub App. For example, if the URL is ",(0,t.jsx)(i.code,{children:"https://github.com/settings/apps/my-test-app"}),", then your app name is ",(0,t.jsx)(i.code,{children:"my-test-app"}),".\nReplace ",(0,t.jsx)(i.code,{children:"<app-id>"})," with the app ID of your GitHub App, which is found in the General -> About section of your GitHub App on GitHub.\nReplace ",(0,t.jsx)(i.code,{children:"<user-id>"})," with the result of running this command ",(0,t.jsx)(i.code,{children:'curl https://api.github.com/users/<app-name>%5Bbot%5D | jq ".id"'}),", where ",(0,t.jsx)(i.code,{children:"<app-name>"})," is the App name you used above."]}),"\n",(0,t.jsxs)(i.p,{children:["Finally, ensure the private key is stored in the ",(0,t.jsx)(i.code,{children:".secrets"})," directory in the root of the Minder repository."]}),"\n",(0,t.jsx)(i.h3,{id:"set-up-a-fallback-token-for-listing-artifacts",children:"Set up a fallback token for listing artifacts"}),"\n",(0,t.jsxs)(i.p,{children:["When using a GitHub App installation token, GitHub does not allow listing artifacts. To work around this, you can create a personal access token, with the scopes ",(0,t.jsx)(i.code,{children:"public_repo"})," and ",(0,t.jsx)(i.code,{children:"read:packages"})," and add it to the ",(0,t.jsx)(i.code,{children:"server-config.yaml"})," file:"]}),"\n",(0,t.jsx)(i.pre,{children:(0,t.jsx)(i.code,{className:"language-yaml",children:"provider:\n  github-app:\n    fallback_token: <personal-access-token>\n"})}),"\n",(0,t.jsx)(i.p,{children:"This token will be used to list artifacts in repositories."}),"\n",(0,t.jsx)(i.h3,{id:"optional-configure-the-webhook",children:"(optional) Configure the webhook"}),"\n",(0,t.jsxs)(i.p,{children:["If you'd like Minder to automatically remove a provider when the GitHub App is uninstalled, you can configure a webhook in the GitHub App settings. The webhook can be configured to send events to ",(0,t.jsx)(i.code,{children:"<your-domain>/api/v1/ghapp/"}),", where ",(0,t.jsx)(i.code,{children:"<your-domain>"})," is the domain where Minder is running."]}),"\n",(0,t.jsxs)(i.p,{children:["Note that if you're running Minder locally, you can use a service like ",(0,t.jsx)(i.a,{href:"https://ngrok.com/",children:"ngrok"})," to expose your local server to the internet."]}),"\n",(0,t.jsx)(i.h2,{id:"create-a-github-oauth-application-option-2",children:"Create a GitHub OAuth Application (option 2)"}),"\n",(0,t.jsx)(i.p,{children:"Alternatively, you can use a GitHub OAuth application to allow users to enroll into Minder. There is no need to creat both a GitHub App and a GitHub OAuth application."}),"\n",(0,t.jsxs)(i.ol,{children:["\n",(0,t.jsxs)(i.li,{children:["Navigate to ",(0,t.jsx)(i.a,{href:"https://github.com/settings/profile",children:"GitHub Developer Settings"})]}),"\n",(0,t.jsx)(i.li,{children:'Select "Developer Settings" from the left hand menu'}),"\n",(0,t.jsx)(i.li,{children:'Select "OAuth Apps" from the left hand menu'}),"\n",(0,t.jsx)(i.li,{children:'Select "New OAuth App"'}),"\n",(0,t.jsxs)(i.li,{children:["Enter the following details:","\n",(0,t.jsxs)(i.ul,{children:["\n",(0,t.jsxs)(i.li,{children:["Application Name: ",(0,t.jsx)(i.code,{children:"Minder"})," (or any other name you like)"]}),"\n",(0,t.jsxs)(i.li,{children:["Homepage URL: ",(0,t.jsx)(i.code,{children:"http://localhost:8080"})]}),"\n",(0,t.jsxs)(i.li,{children:["Authorization callback URL: ",(0,t.jsx)(i.code,{children:"http://localhost:8080/api/v1/auth/callback/github"})]}),"\n",(0,t.jsxs)(i.li,{children:["If you are prompted to enter a ",(0,t.jsx)(i.code,{children:"Webhook URL"}),", deselect the ",(0,t.jsx)(i.code,{children:"Active"})," option in the ",(0,t.jsx)(i.code,{children:"Webhook"})," section."]}),"\n"]}),"\n"]}),"\n",(0,t.jsx)(i.li,{children:'Select "Register Application"'}),"\n",(0,t.jsx)(i.li,{children:"Generate a client secret"}),"\n",(0,t.jsxs)(i.li,{children:['Copy the "Client ID" , "Client Secret" and "Authorization callback URL" values\ninto your ',(0,t.jsx)(i.code,{children:"./server-config.yaml"})," file, under the ",(0,t.jsx)(i.code,{children:"github"})," section."]}),"\n"]}),"\n",(0,t.jsx)(i.p,{children:(0,t.jsx)(i.img,{alt:"github oauth2 page",src:n(25342).A+"",width:"1282",height:"2402"})})]})}function d(e={}){const{wrapper:i}={...(0,r.R)(),...e.components};return i?(0,t.jsx)(i,{...e,children:(0,t.jsx)(h,{...e})}):h(e)}},25342:(e,i,n)=>{n.d(i,{A:()=>t});const t=n.p+"assets/images/minder-server-oauth-202262cad7bcd33bd0856f08a3cf29a2.png"},28453:(e,i,n)=>{n.d(i,{R:()=>s,x:()=>l});var t=n(96540);const r={},o=t.createContext(r);function s(e){const i=t.useContext(o);return t.useMemo((function(){return"function"==typeof e?e(i):{...i,...e}}),[i,e])}function l(e){let i;return i=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:s(e.components),t.createElement(o.Provider,{value:i},e.children)}}}]);