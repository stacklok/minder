"use strict";(self.webpackChunkminder_docs=self.webpackChunkminder_docs||[]).push([[4223],{4409:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>r,default:()=>u,frontMatter:()=>s,metadata:()=>a,toc:()=>h});var i=n(74848),o=n(28453);const s={},r="Writing Custom Rule Types",a={id:"how-to/custom-rules",title:"Writing Custom Rule Types",description:"Minder's policy engine is flexible enough that you can write your own rule types to check for specific settings in your supply chain. This guide will walk you through the process of writing a custom rule type.",source:"@site/docs/how-to/custom-rules.md",sourceDirName:"how-to",slug:"/how-to/custom-rules",permalink:"/how-to/custom-rules",draft:!1,unlisted:!1,tags:[],version:"current",frontMatter:{},sidebar:"minder",previous:{title:"Adding Users to your Project",permalink:"/how-to/add_users_to_project"},next:{title:"Using Mindev to develop and debug rule types",permalink:"/how-to/mindev"}},l={},h=[{value:"Minder policies",id:"minder-policies",level:2},{value:"Rule Types",id:"rule-types",level:2},{value:"Example: Automatically delete head branches",id:"example-automatically-delete-head-branches",level:2},{value:"Ingestion / Evaluation",id:"ingestion--evaluation",level:3},{value:"Alerting",id:"alerting",level:3},{value:"Remediation",id:"remediation",level:3},{value:"Description &amp; Guidance",id:"description--guidance",level:3},{value:"Trying the rule out",id:"trying-the-rule-out",level:2},{value:"Conclusion",id:"conclusion",level:2}];function d(e){const t={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",li:"li",p:"p",pre:"pre",strong:"strong",ul:"ul",...(0,o.R)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(t.h1,{id:"writing-custom-rule-types",children:"Writing Custom Rule Types"}),"\n",(0,i.jsx)(t.p,{children:"Minder's policy engine is flexible enough that you can write your own rule types to check for specific settings in your supply chain. This guide will walk you through the process of writing a custom rule type."}),"\n",(0,i.jsx)(t.h2,{id:"minder-policies",children:"Minder policies"}),"\n",(0,i.jsx)(t.p,{children:"Minder allows you to check and enforce that certain settings are set up for several stages in your supply chain. To configure those settings, you need to create a Profile. This profile is composed of several rules that represent the settings you want in your supply chain. These rules are actually instantiations of another handy object for Minder called Rule Types. These rule types define the nitty-gritty details of how the specific setting you care about will be checked, how you'll be alerted when something goes out of order, and how it will be automatically remediated."}),"\n",(0,i.jsxs)(t.p,{children:["You can browse a curated collection of rule types in the [rules and profiles repository])(",(0,i.jsx)(t.a,{href:"https://github.com/stacklok/minder-rules-and-profiles",children:"https://github.com/stacklok/minder-rules-and-profiles"}),")."]}),"\n",(0,i.jsx)(t.p,{children:"Some of the rules include:"}),"\n",(0,i.jsxs)(t.ul,{children:["\n",(0,i.jsx)(t.li,{children:"Verifying if you have GitHub\u2019s secret scanning enabled"}),"\n",(0,i.jsx)(t.li,{children:"Verifying if your artifacts are signed and verifiable on Sigstore"}),"\n",(0,i.jsx)(t.li,{children:"Verifying that your branch protection settings are secure"}),"\n"]}),"\n",(0,i.jsx)(t.h2,{id:"rule-types",children:"Rule Types"}),"\n",(0,i.jsx)(t.p,{children:"Rule types aren\u2019t particularly complicated. They include the basic structure to get an observed state, evaluate the rule based on that observed state, do actions based on that state, and finally, give you some instructions in case you want to manage things manually."}),"\n",(0,i.jsx)(t.p,{children:"The Rule Type object in YAML looks as follows:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:"---\nversion: v1\ntype: rule-type\nname: my_cool_new_rule\ndescription: // Description goes here\nguidance: // Guidance goes here\ndef:\n  in_entity: repository  // what are we evaluating?\n  param_schema: // parameters go here\n  rule_schema: // rule definition schema goes here\n  # Defines the configuration for ingesting data relevant for the rule\n  ingest: // observed state gets fetched here\n  eval: // evaluation goes here\n  remediation: // fixing the issue goes here\n  alert: // alerting goes here\n"})}),"\n",(0,i.jsx)(t.p,{children:"The following are the components of a rule type:"}),"\n",(0,i.jsxs)(t.ul,{children:["\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"Description"}),": What does the rule do? This is handy to browse through rule types when building a profile."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"Guidance"}),": What do I do if this rule presents a \u201cfailure\u201d? This is handy to inform folks of what to do in case they\u2019re not using automated remediations."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"in_entity"}),": What are we evaluating? This defines the entity that\u2019s being evaluated. It could be repository, artifact, pull_request, and build_environment (coming soon)."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"param_schema"}),": Optional fields to pass to the ingestion (more on this later). This is handy if we need extra data to get the observed state of an entity."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"rule_schema"}),": Optional fields to pass to the evaluation (more on this later). This is handy for customizing how a rule is evaluated."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"Ingest"}),": This step defines how we get the observed state for an entity. It could be a simple REST call, a cloning of a git repo, or even a custom action if it\u2019s a complex rule."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"Eval"}),": This is the evaluation stage, which defines the actual rule evaluation."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"Remediation"}),": How do we fix the issue? This defines the action to be taken when we need to fix an issue. This is what happens when you enable automated remediations."]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.strong,{children:"Alert"}),": How do we notify folks about the issue? This may take the form of a GitHub Security Advisory, but we\u2019ll support more alerting systems in the near future."]}),"\n"]}),"\n",(0,i.jsx)(t.h2,{id:"example-automatically-delete-head-branches",children:"Example: Automatically delete head branches"}),"\n",(0,i.jsx)(t.p,{children:"Let's write a rule type for checking that GitHub automatically deletes branches after a pull request has been merged. While this is not strictly a security setting, it is a good practice to keep your branches clean to avoid confusion."}),"\n",(0,i.jsx)(t.h3,{id:"ingestion--evaluation",children:"Ingestion / Evaluation"}),"\n",(0,i.jsx)(t.p,{children:"The first thing we need to figure out is how to get the observed state of what we want to evaluate on. This is the ingestion part."}),"\n",(0,i.jsxs)(t.p,{children:["Fortunately for us, GitHub keeps up-to-date and extensive documentation on their APIs. A quick internet search leads us to the relevant ",(0,i.jsx)(t.a,{href:"https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#get-a-repository",children:"Repositories API"})," where we can see that a call to the ",(0,i.jsx)(t.code,{children:"/repos/OWNER/REPO"})," endpoint gives us the following key: ",(0,i.jsx)(t.code,{children:"delete_branch_on_merge"}),"."]}),"\n",(0,i.jsx)(t.p,{children:"So, by now we know that we may fetch this information via a simple REST call."}),"\n",(0,i.jsx)(t.p,{children:"The ingestion piece would then look as follows:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:'---\ndef:\n  ...\n  ingest:\n    type: rest\n    rest:\n      endpoint: "/repos/{{.Entity.Owner}}/{{.Entity.Name}}"\n      parse: json\n'})}),"\n",(0,i.jsxs)(t.p,{children:["While you could hard-code the user/org and name of the repository you want to evaluate, that kind of rule is not handy, especially if you want to enroll multiple repositories in Minder. Thus, Minder has a templating system that allows you to base multiple parts of the rule type on the entity you\u2019re evaluating (remember the in_entity part of the rule type?). The fields you may use are part of the entity\u2019s protobuf, which can be found in ",(0,i.jsx)(t.a,{href:"https://minder-docs.stacklok.dev/ref/proto#repository",children:"our documentation"}),"."]}),"\n",(0,i.jsxs)(t.p,{children:["Now, we want to tell Minder what to actually evaluate from that state. This is the evaluation step. In our case, we want to verify that delete_branch_on_merge is set to true. For our intent, we have a very simple evaluation driver that will do the trick just fine! That is the ",(0,i.jsx)(t.a,{href:"https://jqlang.github.io/jq/",children:"jq evaluation type"}),"."]}),"\n",(0,i.jsx)(t.p,{children:"I understand this is not a setting that everybody would want, and, in fact, some folks might want that setting to be off. This is something we can achieve with a simple toggle. To do it, we need to add a rule_schema to our rule, which would allow us to have a configurable setting in our rule."}),"\n",(0,i.jsx)(t.p,{children:"The evaluation would look as follows:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:"---\ndef:\n  rule_schema:\n    type: object\n    properties:\n      enabled:\n        type: boolean\n    required:\n      - enabled\n  eval:\n    type: jq\n    jq:\n    - ingested:\n        def: '.delete_branch_on_merge'\n      profile:\n        def: \".enabled\"\n"})}),"\n",(0,i.jsx)(t.p,{children:"The rule type above now allows us to compare the delete_branch_on_merge setting we got from the GitHub call, and evaluate it against the enabled setting we've registered for our rule type."}),"\n",(0,i.jsx)(t.h3,{id:"alerting",children:"Alerting"}),"\n",(0,i.jsx)(t.p,{children:"We'll now describe how you may get a notification if your repository doesn\u2019t adhere to the rule. This is as simple as adding the following to the manifest:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:'---\ndef:\n  alert:\n    type: security_advisory\n    security_advisory:\n      severity: "low"\n'})}),"\n",(0,i.jsx)(t.p,{children:"This will create a security advisory in your GitHub repository that you\u2019ll be able to browse for information. Minder knows already what information to fill-in to make the alert relevant."}),"\n",(0,i.jsx)(t.h3,{id:"remediation",children:"Remediation"}),"\n",(0,i.jsx)(t.p,{children:"Minder has the ability to auto-fix issues that it finds in your supply chain, let\u2019s add an automated fix to this rule! Similarly to ingestion, remediations also have several flavors or types. For our case, a simple REST remediation suffices."}),"\n",(0,i.jsx)(t.p,{children:"Let\u2019s see how it would look:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:'---\ndef:\n  remediate:\n    type: rest\n    rest:\n      method: PATCH\n      endpoint: "/repos/{{.Entity.Owner}}/{{.Entity.Name}}"\n      body: |\n        { "delete_branch_on_merge": {{ .Profile.enabled }} }\n'})}),"\n",(0,i.jsxs)(t.p,{children:["This effectively would do a PATCH REST call to the GitHub API if it finds that the rule is out of compliance. We\u2019re able to parametrize the call with whatever we defined in the profile using golang templates (that\u2019s the ",(0,i.jsx)(t.code,{children:"{{ .Profile.enabled }}"})," section you see in the message\u2019s body)."]}),"\n",(0,i.jsx)(t.h3,{id:"description--guidance",children:"Description & Guidance"}),"\n",(0,i.jsx)(t.p,{children:"There are a couple of sections that allow us to give information to rule type users about the rule and what to do with it. These are the description and guidance. The description is simply a textual representation of what the rule type should do. Guidance is the text that will show up if the rule fails. Guidance is relevant when automatic remediations are not enabled, and we want to give folks instructions on what to do to fix the issue."}),"\n",(0,i.jsx)(t.p,{children:"For our rule, they will look as follows:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:'---\nversion: v1\ntype: rule-type\nname: my_cool_new_rule\ncontext:\n  provider: github\ndescription: |\n  This rule verifies that branches are deleted automatically once a pull\n  request merges.\nguidance: |\n  To manage whether branches should be automatically deleted for your repository\n  you need to toggle the "Automatically delete head branches" setting in the\n  general configuration of your repository.\n\n  For more information, see the GitHub documentation on the topic: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-the-automatic-deletion-of-branches\n'})}),"\n",(0,i.jsx)(t.h2,{id:"trying-the-rule-out",children:"Trying the rule out"}),"\n",(0,i.jsxs)(t.p,{children:["The whole rule can be seen in the ",(0,i.jsx)(t.a,{href:"https://github.com/stacklok/minder-rules-and-profiles",children:"Rules and Profiles GitHub repository"}),". In order to try it out, we\u2019ll use the minder CLI, which points to the Minder server hosted by your friends at Stacklok."]}),"\n",(0,i.jsx)(t.p,{children:"Before continuing, make sure you use our Quickstart to install the CLI and enroll your GitHub repos."}),"\n",(0,i.jsx)(t.p,{children:"Let\u2019s create the rule:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"$ minder ruletype create -f rules/github/automatic_branch_deletion.yaml                                   \n"})}),"\n",(0,i.jsxs)(t.p,{children:["Here, you can already see how the description gets displayed. This same description will be handy when browsing rules through ",(0,i.jsx)(t.code,{children:"minder ruletype list"}),"."]}),"\n",(0,i.jsx)(t.p,{children:"Let\u2019s now try it out! We can call our rule in a profile as follows:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:'---\nversion: v1\ntype: profile\nname: degustation-profile\ncontext:\n  provider: github\nalert: "on"\nremediate: "off"\nrepository:\n  - type: automatic_branch_deletion\n    def:\n      enabled: true\n'})}),"\n",(0,i.jsx)(t.p,{children:"We\u2019ll call this degustation-profile.yaml. Let\u2019s create it!"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"$  minder profile create -f degustation-profile.yaml\n"})}),"\n",(0,i.jsx)(t.p,{children:"Now, let's view the status of the profile:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"$ minder profile status list -n degustation-profile -d\n"})}),"\n",(0,i.jsx)(t.p,{children:"Depending on how your repository is set up, you may see a failure or a success. If you see a failure, you can enable automated remediations and see how Minder fixes the issue for you."}),"\n",(0,i.jsx)(t.h2,{id:"conclusion",children:"Conclusion"}),"\n",(0,i.jsx)(t.p,{children:"We\u2019ve now created a basic new rule for Minder. There are more ingestion types, rule evaluation engines, and remediation types that we can use today, and there will be more in the future! If you need support writing your own rule types, feel free to reach out to the Minder team."})]})}function u(e={}){const{wrapper:t}={...(0,o.R)(),...e.components};return t?(0,i.jsx)(t,{...e,children:(0,i.jsx)(d,{...e})}):d(e)}},28453:(e,t,n)=>{n.d(t,{R:()=>r,x:()=>a});var i=n(96540);const o={},s=i.createContext(o);function r(e){const t=i.useContext(s);return i.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function a(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(o):e.components||o:r(e.components),i.createElement(s.Provider,{value:t},e.children)}}}]);