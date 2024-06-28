"use strict";(self.webpackChunkminder_docs=self.webpackChunkminder_docs||[]).push([[3852],{92660:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>c,contentTitle:()=>o,default:()=>h,frontMatter:()=>i,metadata:()=>l,toc:()=>a});var n=r(74848),s=r(28453);const i={title:"Trusty",sidebar_position:40},o="Trusty Integration",l={id:"integrations/trusty",title:"Trusty",description:"Minder integrates directly with Trusty by Stacklok to enable policy-driven dependency management based on the risk level of dependencies.",source:"@site/docs/integrations/trusty.md",sourceDirName:"integrations",slug:"/integrations/trusty",permalink:"/integrations/trusty",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:40,frontMatter:{title:"Trusty",sidebar_position:40},sidebar:"minder",previous:{title:"OSS tooling integrations",permalink:"/integrations/community_integrations"},next:{title:"Run the server",permalink:"/run_minder_server/run_the_server"}},c={},a=[{value:"Create the rule type",id:"create-the-rule-type",level:2},{value:"Create a profile",id:"create-a-profile",level:2}];function d(e){const t={a:"a",code:"code",h1:"h1",h2:"h2",img:"img",li:"li",p:"p",pre:"pre",ul:"ul",...(0,s.R)(),...e.components};return(0,n.jsxs)(n.Fragment,{children:[(0,n.jsx)(t.h1,{id:"trusty-integration",children:"Trusty Integration"}),"\n",(0,n.jsxs)(t.p,{children:["Minder integrates directly with ",(0,n.jsx)(t.a,{href:"http://trustypkg.dev",children:"Trusty by Stacklok"})," to enable policy-driven dependency management based on the risk level of dependencies."]}),"\n",(0,n.jsxs)(t.p,{children:["Minder provides a ",(0,n.jsx)(t.a,{href:"/ref/rules/pr_trusty_check",children:"Trusty rule type"})," which allows you to monitor new pull requests for newly added dependencies with low ",(0,n.jsx)(t.a,{href:"https://www.trustypkg.dev/",children:"Trusty"})," scores."]}),"\n",(0,n.jsx)(t.p,{children:"For every pull request submitted to a repository, this rule will check if the pull request adds a new dependency with\na Trusty score below a threshold that you define. If a dependency with a low score is added, Minder will notify you and\nsuggest an alternative package, if one is available."}),"\n",(0,n.jsx)(t.p,{children:"Here we see Minder in action, commenting on a pull request that adds a package with a low Trusty score:"}),"\n",(0,n.jsx)(t.p,{children:(0,n.jsx)(t.img,{alt:"Minder commenting on PR with low Trusty score",src:r(85662).A+"",width:"1882",height:"672"})}),"\n",(0,n.jsx)(t.h2,{id:"create-the-rule-type",children:"Create the rule type"}),"\n",(0,n.jsxs)(t.p,{children:["Once you have ",(0,n.jsx)(t.a,{href:"/getting_started/login",children:"a Minder account"}),", you can create a new rule of type ",(0,n.jsx)(t.code,{children:"pr_trusty_check"})," to monitor your pull requests for untrustworthy packages."]}),"\n",(0,n.jsx)(t.p,{children:"The rule type is one of the reference rule types provided by the Minder team."}),"\n",(0,n.jsxs)(t.p,{children:["Fetch all the reference rules by cloning the ",(0,n.jsx)(t.a,{href:"https://github.com/stacklok/minder-rules-and-profiles",children:"minder-rules-and-profiles repository"}),"."]}),"\n",(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:"git clone https://github.com/stacklok/minder-rules-and-profiles.git\n"})}),"\n",(0,n.jsx)(t.p,{children:"In that directory, you can find all the reference rules and profiles."}),"\n",(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:"cd minder-rules-and-profiles\n"})}),"\n",(0,n.jsxs)(t.p,{children:["Create the ",(0,n.jsx)(t.code,{children:"pr_trusty_check"})," rule type in Minder:"]}),"\n",(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:"minder ruletype create -f rule-types/github/pr_trusty_check.yaml\n"})}),"\n",(0,n.jsx)(t.h2,{id:"create-a-profile",children:"Create a profile"}),"\n",(0,n.jsx)(t.p,{children:"Next, create a profile that applies the rule to all registered repositories."}),"\n",(0,n.jsxs)(t.p,{children:["Create a new file called ",(0,n.jsx)(t.code,{children:"low-trusty-score-profile.yaml"}),". In this profile the following options are configured:"]}),"\n",(0,n.jsxs)(t.ul,{children:["\n",(0,n.jsxs)(t.li,{children:[(0,n.jsx)(t.code,{children:"action"})," is set to ",(0,n.jsx)(t.code,{children:"summary"})," allowing Minder to comment on pull requests with a low Trusty score, providing an explanation of the issue and possible alternatives."]}),"\n",(0,n.jsxs)(t.li,{children:[(0,n.jsx)(t.code,{children:"ecosystem_config"})," is set to check the ",(0,n.jsx)(t.code,{children:"pypi"})," ecosystem for new dependencies whose Trusty score is below the threshold of 5."]}),"\n"]}),"\n",(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-yaml",children:'---\nversion: v1\ntype: profile\nname: low-trusty-score-profile\ncontext:\n  provider: github\nremediate: "on"\npull_request:\n  - type: pr_trusty_check\n    def:\n      action: summary\n      ecosystem_config:\n        - name: pypi\n          score: 5\n'})}),"\n",(0,n.jsx)(t.p,{children:"Create the profile in Minder:"}),"\n",(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:"minder profile create -f low-trusty-score-profile.yaml\n"})}),"\n",(0,n.jsx)(t.p,{children:"That's it! Any registered repos will now be monitored for new dependencies with low Trusty scores."})]})}function h(e={}){const{wrapper:t}={...(0,s.R)(),...e.components};return t?(0,n.jsx)(t,{...e,children:(0,n.jsx)(d,{...e})}):d(e)}},85662:(e,t,r)=>{r.d(t,{A:()=>n});const n=r.p+"assets/images/low-trusty-score-pr-759ac4bb814fada4113e857d68fcbd75.png"},28453:(e,t,r)=>{r.d(t,{R:()=>o,x:()=>l});var n=r(96540);const s={},i=n.createContext(s);function o(e){const t=n.useContext(i);return n.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function l(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(s):e.components||s:o(e.components),n.createElement(i.Provider,{value:t},e.children)}}}]);