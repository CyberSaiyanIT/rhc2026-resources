"""Participant lab portal: one static page that polls /api/state and drives the scenario."""
import json
from html import escape

from .runtime import PHASES
from .style import CREAM, INK, LINE, MAGENTA, MONO, MUTED, PANEL, PAPER, PAPER_LINE, PAPER_MAGENTA, PAPER_MUTED, PAPER_PANEL, SANS

# What each phase asks of your workflow; C3 is optional.
GOALS = {
    'Base': 'Receive an alert in your n8n workflow.',
    'A': 'Block every alerted source.',
    'B': 'Consult reputation before blocking.',
    'C1': 'Let an AI agent investigate before deciding.',
    'C2': 'Require a human approval before any block.',
    'C3': 'Optional: a temporary block that expires by itself.',
}
API_BASE = 'http://workshop:8000'

CSS = f'''
:root{{color-scheme:dark light;--bg:{INK};--panel:{PANEL};--line:{LINE};--text:{CREAM};--muted:{MUTED};--accent:{MAGENTA};--on-accent:#fff;--bad:#ef5350;--good:#43c78a}}
@media (prefers-color-scheme:light){{:root{{--bg:{PAPER};--panel:{PAPER_PANEL};--line:{PAPER_LINE};--text:{INK};--muted:{PAPER_MUTED};--accent:{PAPER_MAGENTA};--bad:#c62828;--good:#1b7f4f}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 {SANS}}}
body:has(#production[data-color=red]){{--alarm-low:#210b13;--alarm-high:#7c182b;animation:screen-alert 3s ease-in-out infinite}}
@media (prefers-color-scheme:light){{body:has(#production[data-color=red]){{--alarm-low:#fff0f0;--alarm-high:#ed9da5}}}}
@keyframes screen-alert{{0%,100%{{background-color:var(--alarm-low)}}50%{{background-color:var(--alarm-high)}}}}
@media (prefers-reduced-motion:reduce){{body:has(#production[data-color=red]){{animation:none;background-color:var(--alarm-high)}}}}
main{{position:relative;z-index:1;max-width:880px;margin:0 auto;padding:2rem 1rem 3rem}}
.frame{{border:2px solid var(--text);box-shadow:6px 6px 0 var(--accent);padding:1.75rem clamp(1rem,4vw,2rem)}}
header{{text-align:center;margin-bottom:1.5rem}}
.mark{{font:bold 1.9rem {MONO};letter-spacing:3px}}.mark span{{color:var(--accent)}}
.kicker,.label,th{{font:600 .75rem {MONO};letter-spacing:2px;text-transform:uppercase}}
.kicker{{color:var(--accent);margin:.1rem 0 .35rem}}
h1{{margin:0;font-size:1.6rem}}h1 span{{color:var(--accent)}}
.sub{{margin:.2rem 0 0;font:.85rem {MONO};color:var(--muted)}}
.lab-guardians{{display:none;position:fixed;inset:0;z-index:0;overflow:hidden;pointer-events:none;user-select:none}}
.guardian{{--side-slot:clamp(8rem,calc((100vw - 880px)/2 - 1rem),20rem);position:absolute;top:60%;width:var(--side-slot);height:min(calc(var(--side-slot)*2),55vh,32rem);margin:0;color:var(--aura)}}
.guardian-goku{{--aura:#ffc44a;--aura-soft:#ffd66c35;--entry-x:-36px;left:calc((100vw - 880px)/4);transform:translate(-50%,-50%)}}
.guardian-kai{{--aura:#75d8ff;--aura-soft:#75d8ff28;--entry-x:36px;right:calc((100vw - 880px)/4);transform:translate(50%,-50%)}}
.guardian-frieza{{--aura:#cb83ff;--aura-soft:#cb83ff30;--entry-x:60px;right:calc((100vw - 880px)/4);transform:translate(50%,-50%);display:none}}
body:has(.manga-dialogue[data-speaker=frieza]):has(#production[data-color=yellow]) .guardian-kai{{display:none}}
body:has(.manga-dialogue[data-speaker=frieza]):has(#production[data-color=yellow]) .guardian-frieza{{display:block}}
.guardian-frieza .guardian-image{{animation:guardian-hover 4s ease-in-out infinite}}
.guardian-stage{{position:relative;width:100%;height:100%;isolation:isolate}}
.guardian-glow{{position:absolute;z-index:-1;inset:-8% -5%;background:radial-gradient(ellipse at 50% 60%,var(--aura-soft),transparent 72%);animation:guardian-glow 4.5s ease-in-out infinite}}
.guardian-aura{{position:absolute;z-index:-1;inset:-3% -2% 0;width:104%;height:103%;color:var(--aura);filter:drop-shadow(0 0 5px var(--aura));animation:guardian-energy 3.8s steps(4,end) infinite}}
.guardian-kai .guardian-aura{{opacity:.55;animation-duration:6s}}
.guardian-entry{{position:absolute;inset:0;animation:guardian-arrival 1.1s ease-out both}}
.guardian-image{{display:block;width:100%;height:100%;object-fit:contain;image-rendering:pixelated;filter:drop-shadow(0 0 2px var(--aura));transform-origin:50% 90%;animation:guardian-breathe 3.2s steps(3,end) infinite}}
.guardian-kai .guardian-image{{animation:guardian-hover 5s ease-in-out infinite}}
.guardian figcaption{{position:absolute;left:0;right:0;top:calc(100% + .75rem);text-align:center;color:var(--text);font:bold .85rem {MONO};letter-spacing:3px}}
.guardian figcaption::after{{content:"";display:block;width:2.5rem;height:2px;margin:.5rem auto 0;background:var(--aura)}}
.guardian-sparks{{position:absolute;inset:0}}
.guardian-sparks i{{position:absolute;left:14%;bottom:12%;width:4px;height:4px;background:var(--aura);box-shadow:0 0 4px var(--aura);opacity:0;animation:guardian-spark 7s steps(18,end) infinite}}
.guardian-sparks i:nth-child(2){{left:34%;width:3px;height:3px;animation-delay:-1.4s}}
.guardian-sparks i:nth-child(3){{left:68%;animation-delay:-3.1s}}
.guardian-sparks i:nth-child(4){{left:88%;width:3px;height:3px;animation-delay:-4.6s}}
.guardian-sparks i:nth-child(5){{left:48%;animation-delay:-5.8s}}
.guardian-kai .guardian-sparks i{{animation-duration:9s}}
@keyframes guardian-arrival{{from{{opacity:0;transform:translateX(var(--entry-x))}}to{{opacity:1;transform:translateX(0)}}}}
@keyframes guardian-breathe{{0%,100%{{transform:translateY(0) scaleY(1)}}50%{{transform:translateY(-2px) scaleY(1.008)}}}}
@keyframes guardian-hover{{0%,100%{{transform:translateY(3px) rotate(-.5deg)}}50%{{transform:translateY(-7px) rotate(.5deg)}}}}
@keyframes guardian-glow{{0%,100%{{opacity:.65}}50%{{opacity:1}}}}
@keyframes guardian-energy{{0%,100%{{transform:scaleX(.97);filter:drop-shadow(0 0 3px var(--aura))}}50%{{transform:scaleX(1.02);filter:drop-shadow(0 0 8px var(--aura))}}}}
@keyframes guardian-spark{{0%{{opacity:0;transform:translateY(0)}}12%{{opacity:.8}}80%{{opacity:.35}}100%{{opacity:0;transform:translateY(clamp(-22rem,-40vh,-10rem))}}}}
@media(min-width:1200px) and (hover:hover) and (pointer:fine){{.lab-guardians{{display:block}}}}
@media(prefers-reduced-motion:reduce){{.lab-guardians *{{animation:none!important}}.guardian-sparks{{display:none}}}}
.manga-dialogue{{display:none;margin:0 0 1.5rem}}
.manga-exchange{{display:flex;gap:.8rem}}
.manga-balloon{{position:relative;flex:1;min-width:0;margin:0;padding:.9rem .8rem;background:#fffdf7;color:#151019;border:3px solid #151019;border-radius:20px 18px 24px 16px;box-shadow:4px 4px 0 #151019;font:700 .85rem/1.4 {SANS};overflow-wrap:anywhere;animation:balloon-arrival .35s ease-out both}}
.manga-balloon strong{{display:block;margin-bottom:.35rem;font:bold .65rem {MONO};letter-spacing:1px;color:#704100}}
.manga-balloon[data-character="King Kai"] strong{{color:#00566e}}
.manga-balloon[data-character=Frieza] strong{{color:#76359b}}
.manga-balloon::after{{content:"";position:absolute;bottom:-13px;left:24%;width:18px;height:18px;background:#fffdf7;border-right:3px solid #151019;border-bottom:3px solid #151019;transform:skewY(25deg) rotate(35deg)}}
@keyframes balloon-arrival{{from{{opacity:0}}to{{opacity:1}}}}
@media(min-width:1200px) and (hover:hover) and (pointer:fine){{.manga-dialogue{{display:block;margin:0}}.manga-balloon{{position:fixed;z-index:2;top:7rem;width:clamp(8rem,calc((100vw - 880px)/2 - 1.75rem),19rem);font-size:clamp(.75rem,.9vw,.95rem)}}.manga-balloon:first-child{{left:calc((100vw - 880px)/4);transform:translateX(-50%)}}.manga-balloon:last-child{{right:calc((100vw - 880px)/4);transform:translateX(50%)}}}}
@media(prefers-reduced-motion:reduce){{.manga-balloon{{animation:none}}}}
.namek-banner{{--pod-size:clamp(6.5rem,22vw,10rem);--shield-size:clamp(9rem,29vw,13rem);--defense-left:clamp(.3rem,5vw,2.25rem);--pod-travel:0px;--shot-start-x:calc(96% - var(--pod-size)*.9 + var(--pod-travel));--shot-start-y:calc(8% + var(--pod-size)*.51);--shot-end-x:calc(var(--defense-left) + var(--shield-size)*.77);--shot-end-y:calc(100% - var(--shield-size)*.24 - .5rem);--impact-color:#ffc865;position:relative;isolation:isolate;height:clamp(10.5rem,28vw,14rem);margin:0 0 1.5rem;overflow:hidden;border:2px solid var(--text);box-shadow:4px 4px 0 var(--accent);background:#07352d}}
.namek-landscape{{display:block;width:100%;height:100%;object-fit:cover;object-position:center 60%;image-rendering:pixelated}}
.namek-banner figcaption{{position:absolute;z-index:5;right:.55rem;bottom:.55rem;padding:.2rem .5rem;border:1px solid {MAGENTA};background:{INK};color:{CREAM};font:bold .68rem {MONO};letter-spacing:1.5px}}
.namek-battle{{position:absolute;inset:0;pointer-events:none}}
.namek-pod{{position:absolute;z-index:3;right:4%;top:8%;width:var(--pod-size);transition:transform .8s steps(8,end),opacity .8s}}
.namek-pod-entry{{animation:namek-arrival 1.5s steps(18,end) both}}
.namek-pod img{{display:block;width:100%;height:auto;image-rendering:pixelated;animation:namek-hover 3s steps(4,end) infinite}}
.namek-defense{{position:absolute;left:var(--defense-left);bottom:.5rem;width:var(--shield-size);height:var(--shield-size)}}
.namek-defender{{position:absolute;z-index:2;left:8%;bottom:10%;height:78%;width:58%;object-fit:contain;image-rendering:pixelated}}
.namek-outpost{{position:absolute;right:10%;bottom:7%;width:52%;height:43%;object-fit:contain;object-position:center bottom;image-rendering:pixelated;filter:drop-shadow(0 3px 0 #123d36)}}
.namek-shield{{position:absolute;z-index:4;inset:0;width:100%;height:100%;opacity:0;transform:scale(.92);transform-origin:50% 92%;transition:opacity .6s,transform .6s steps(6,end);filter:drop-shadow(0 0 3px #73f8d4)}}
.namek-palm{{position:absolute;z-index:5;left:61%;top:39%;width:5px;height:5px;background:#efffff;box-shadow:0 0 5px 2px #9bf9e6,0 0 12px 3px #56ddb888;opacity:0;transition:opacity .6s}}
.namek-shield-hit{{opacity:0;animation:namek-field-hit 7s steps(4,end) infinite}}
.namek-hit-second{{animation-delay:.28s}}.namek-hit-third{{animation-delay:.56s}}
.namek-shots,.namek-impacts{{display:none}}
.namek-shot{{position:absolute;z-index:3;left:var(--shot-start-x);top:var(--shot-start-y);width:1.3rem;height:5px;background:#fff1ff;border-left:5px solid #d64aff;box-shadow:5px 0 #942bb8,0 0 5px #e394ff;opacity:0;transform:rotate(-15deg);animation:namek-shot 7s linear infinite}}
.namek-impact{{position:absolute;z-index:5;left:var(--shot-end-x);top:var(--shot-end-y);width:1.8rem;height:1.8rem;overflow:visible;color:var(--impact-color);opacity:0;animation:namek-impact 7s steps(4,end) infinite}}
.namek-shot:nth-child(2),.namek-impact:nth-child(2){{animation-delay:.28s}}
.namek-shot:nth-child(3),.namek-impact:nth-child(3){{animation-delay:.56s}}
body:has(#production[data-color=yellow]) .namek-shots,body:has(#production[data-color=yellow]) .namek-impacts,body:has(#production[data-color=green]) .namek-shots,body:has(#production[data-color=green]) .namek-impacts{{display:block}}
body:has(#production[data-color=green]) .namek-banner{{--pod-travel:1rem;--shot-end-x:calc(var(--defense-left) + var(--shield-size)*.9111);--shot-end-y:calc(100% - var(--shield-size)*.46 - .5rem);--impact-color:#95fff2}}
body:has(#production[data-color=green]) .namek-shield{{opacity:1;transform:scale(1);animation:namek-shield 4s ease-in-out infinite}}
body:has(#production[data-color=green]) .namek-palm{{opacity:.9}}
body:has(#production[data-color=green]) .namek-pod{{transform:translateX(var(--pod-travel)) rotate(5deg);opacity:.8}}
body:has(#production[data-color=green]) .namek-defender{{animation:namek-brace 3s steps(2,end) infinite}}
body:has(#production[data-color=red]) .namek-banner{{border-color:#ef5350}}
body:has(#production[data-color=gray]) .namek-pod{{opacity:.45}}
@keyframes namek-arrival{{from{{transform:translateX(calc(100% + 20vw))}}to{{transform:translateX(0)}}}}
@keyframes namek-hover{{0%,100%{{transform:translateY(0)}}50%{{transform:translateY(-5px)}}}}
@keyframes namek-shot{{0%,43%{{left:var(--shot-start-x);top:var(--shot-start-y);opacity:0}}44%{{opacity:1}}61%{{left:var(--shot-end-x);top:var(--shot-end-y);opacity:1}}62%,100%{{left:var(--shot-end-x);top:var(--shot-end-y);opacity:0}}}}
@keyframes namek-impact{{0%,60%,73%,100%{{opacity:0;transform:translate(-50%,-50%) scale(.5)}}62%{{opacity:1;transform:translate(-50%,-50%) scale(1)}}70%{{opacity:0;transform:translate(-50%,-50%) scale(1.7)}}}}
@keyframes namek-field-hit{{0%,60%,73%,100%{{opacity:0}}62%{{opacity:.9}}70%{{opacity:0}}}}
@keyframes namek-shield{{0%,100%{{filter:drop-shadow(0 0 3px #73f8d4)}}50%{{filter:drop-shadow(0 0 6px #73f8d4)}}}}
@keyframes namek-brace{{0%,100%{{transform:translateX(0)}}50%{{transform:translateX(2px)}}}}
@media (prefers-reduced-motion:reduce){{.namek-battle *{{animation:none!important;transition:none!important}}.namek-shots,.namek-impacts{{display:none!important}}}}
section{{background:var(--panel);border-left:4px solid var(--accent);padding:1rem 1.25rem;margin-top:1.25rem}}
h2{{margin:0 0 .75rem;font:bold .85rem {MONO};letter-spacing:2px;text-transform:uppercase;color:var(--accent)}}
h3{{margin:1rem 0 .25rem;font:600 .9rem {SANS}}}
.facts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:.75rem 1.5rem;margin:0 0 1rem}}
.facts div{{min-width:0}}.label{{color:var(--muted);display:block}}.login{{display:block;font-size:.8rem;color:var(--muted)}}
code{{font-family:{MONO};font-size:.9em;overflow-wrap:anywhere}}
a{{color:var(--accent)}}
.btn{{display:inline-block;max-width:100%;min-height:44px;padding:.6rem 1.1rem;font:bold .85rem {MONO};letter-spacing:1px;text-transform:uppercase;text-align:center;text-decoration:none;cursor:pointer;border:2px solid var(--accent);background:var(--accent);color:var(--on-accent)}}
.btn.ghost{{background:transparent;color:var(--text);border-color:var(--line)}}
.btn:hover,.btn:focus-visible{{box-shadow:3px 3px 0 var(--text);outline:none}}
.btn:disabled{{cursor:wait;opacity:.5;box-shadow:none}}
.row{{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center}}
.badge{{display:inline-block;padding:.05rem .5rem;font:600 .75rem {MONO};letter-spacing:1px;text-transform:uppercase;border:1px solid var(--muted);color:var(--muted)}}
.badge.good{{border-color:var(--accent);background:var(--accent);color:var(--on-accent)}}
.badge.bad{{border-color:var(--bad);color:var(--bad)}}
.scroll{{overflow-x:auto;max-width:100%;overscroll-behavior-x:contain}}
table{{width:100%;border-collapse:collapse;font-size:.92rem}}
th{{text-align:left;color:var(--muted);padding:.35rem .6rem .35rem 0;border-bottom:1px solid var(--line);white-space:nowrap}}
td{{padding:.45rem .6rem .45rem 0;border-bottom:1px solid var(--line);vertical-align:top}}
td small{{display:block;color:var(--muted)}}
tr:last-child td{{border-bottom:0}}
.empty,.hint,.live{{margin:.6rem 0 0;font-size:.85rem;color:var(--muted)}}
.empty{{margin:0}}
.notice{{min-height:1.4em;margin:.6rem 0 0;font-size:.85rem}}
.notice[data-error]{{color:var(--bad);font-weight:700}}
.callout{{margin:0 0 .9rem;padding:.75rem 1rem;border:2px solid var(--bad);color:var(--text)}}
.callout strong{{display:block;color:var(--bad);font:bold .8rem {MONO};letter-spacing:1px;text-transform:uppercase}}
.callout p{{margin:.3rem 0 0}}
.error{{color:var(--bad);font-weight:700}}
.phases{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,12.5rem),1fr));gap:.65rem;margin:0 0 .9rem}}
.phase{{display:flex;flex-direction:column;gap:.45rem;padding:.75rem;border:1px solid var(--line)}}
.phase[data-current]{{border:2px solid var(--accent);box-shadow:3px 3px 0 var(--accent)}}
.phase-name{{display:flex;justify-content:space-between;gap:.5rem;font:bold 1rem {MONO}}}
.phase-name span{{font:600 .7rem {MONO};letter-spacing:1px;text-transform:uppercase;color:var(--muted)}}
.phase-done,.phase-now{{display:none}}
.phase[data-done] .phase-done,.phase[data-current] .phase-now{{display:inline}}
.phase-done{{color:var(--good)!important}}.phase-now{{color:var(--accent)!important}}
.phase p{{flex:1;margin:0;font-size:.88rem}}
.phase .btn{{width:100%;padding:.45rem .6rem;min-height:40px}}
.checklist{{margin:0;padding:0;list-style:none}}
.checklist li{{display:flex;gap:.6rem;padding:.3rem 0}}
.checklist li::before{{content:"\\25CB";flex:none;width:1.2rem;color:var(--muted)}}
.checklist li[data-done]::before{{content:"\\2714";color:var(--good)}}
.checklist small{{margin-left:auto;padding-left:.5rem;font:600 .7rem {MONO};letter-spacing:1px;text-transform:uppercase;color:var(--muted)}}
.approvals{{margin:0;padding:0;list-style:none;display:grid;gap:.6rem}}
.approvals li{{display:flex;flex-wrap:wrap;gap:.6rem 1rem;align-items:center;justify-content:space-between;padding:.6rem .75rem;border:2px solid var(--accent)}}
.production{{border-left-color:var(--muted)}}
.production[data-color=red]{{border-left-color:#ef5350;outline:2px solid #ef5350;box-shadow:0 0 24px #ef535055}}
.production[data-color=yellow]{{border-left-color:#f5cc47}}
.production[data-color=green]{{border-left-color:#43c78a}}
.production-heading{{display:flex;align-items:center;gap:.8rem;margin-bottom:.5rem}}
.production-heading h2{{margin:0;min-width:0;overflow-wrap:anywhere;color:var(--text);letter-spacing:0;text-transform:none;font:700 1.1rem {SANS}}}
.production-lamp{{display:grid;place-items:center;flex:none;width:3rem;height:3rem}}
.production-lamp svg{{display:none;width:100%;height:100%;overflow:visible}}
.production[data-color=gray] .indicator-gray,.production[data-color=red] .indicator-red,.production[data-color=yellow] .indicator-yellow,.production[data-color=green] .indicator-green{{display:block}}
.production[data-color=red] .indicator-red{{animation:indicator-red 1.8s ease-in-out infinite}}
.production[data-color=yellow] .indicator-yellow{{animation:indicator-yellow 2.4s steps(2,end) infinite}}
.production[data-color=green] .indicator-green{{animation:indicator-green 3s ease-in-out infinite}}
@keyframes indicator-red{{0%,100%{{transform:scale(1);filter:drop-shadow(0 0 2px #ef5350)}}50%{{transform:scale(1.1);filter:drop-shadow(0 0 10px #ef5350)}}}}
@keyframes indicator-yellow{{0%,100%{{transform:translateY(0);filter:drop-shadow(0 0 2px #f5cc47)}}50%{{transform:translateY(-3px);filter:drop-shadow(0 0 7px #f5cc47)}}}}
@keyframes indicator-green{{0%,100%{{filter:drop-shadow(0 0 2px #43c78a)}}50%{{filter:drop-shadow(0 0 9px #43c78a)}}}}
@media (prefers-reduced-motion:reduce){{.production-lamp svg{{animation:none!important}}}}
.production p{{margin:.35rem 0}}
.scouter-alert{{display:none;align-items:center;gap:.75rem;margin:.8rem 0;padding:.55rem .75rem;border:2px solid #d5a92d;background:#101b13;color:#d6ffb5;font:bold .75rem {MONO};letter-spacing:1px;text-transform:uppercase}}
.production[data-color=yellow] .scouter-alert{{display:flex}}
.scouter-screen{{position:relative;flex:none;width:2.4rem;height:2.4rem;overflow:hidden;border:2px solid #a5ee73;background:repeating-linear-gradient(0deg,transparent 0 7px,#426843 7px 8px),repeating-linear-gradient(90deg,#14251a 0 7px,#426843 7px 8px)}}
.scouter-screen::before{{content:"";position:absolute;left:50%;top:50%;width:47%;height:2px;background:#dcffa6;box-shadow:0 0 6px #a5ee73;transform-origin:left center;animation:scouter-sweep 2.4s steps(12,end) infinite}}
.scouter-screen::after{{content:"";position:absolute;right:23%;top:22%;width:5px;height:5px;background:#ff6262;box-shadow:0 0 5px #ff6262}}
@keyframes scouter-sweep{{to{{transform:rotate(360deg)}}}}
@media (prefers-reduced-motion:reduce){{.scouter-screen::before{{animation:none;transform:rotate(-35deg)}}}}
.production-clients{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,18rem),1fr));gap:.65rem;padding:0;margin:1rem 0;list-style:none}}
.production-clients li{{position:relative;min-height:7.4rem;overflow:hidden;border:1px solid var(--line);border-bottom:3px solid var(--accent);padding:.8rem .65rem .7rem 6rem;background:{INK};color:{CREAM}}}
.production-clients li::before{{content:"";position:absolute;left:.55rem;bottom:.25rem;width:4.8rem;height:6.7rem;background-repeat:no-repeat;background-position:center bottom;background-size:contain;image-rendering:pixelated;animation:sprite-idle 2s steps(2,end) infinite}}
.production-clients li:nth-child(1)::before{{background-image:url("/assets/frieza.png")}}
.production-clients li:nth-child(2)::before{{background-image:url("/assets/namekian.png");animation-delay:-.45s}}
.production-clients li:nth-child(3)::before{{background-image:url("/assets/bulma.png");animation-delay:-.9s}}
.production-clients li:nth-child(4)::before{{background-image:url("/assets/piccolo.png");animation-delay:-1.35s}}
.production-clients li[data-connectivity=blocked]{{border-bottom-color:#ef5350}}
.production-clients li[data-connectivity=connected]{{border-bottom-color:#43c78a}}
.production-clients small{{display:block;color:#b9b7c0;overflow-wrap:anywhere}}
.production-clients strong{{display:block;line-height:1.3;margin-bottom:.25rem}}
@keyframes sprite-idle{{0%,100%{{transform:translateY(0)}}50%{{transform:translateY(-3px)}}}}
@media (prefers-reduced-motion:reduce){{.production-clients li::before{{animation:none}}}}
.production-error{{border-left:3px solid #ef5350;padding:.5rem .75rem}}
details>summary{{cursor:pointer;font:bold .85rem {MONO};letter-spacing:2px;text-transform:uppercase;color:var(--accent)}}
details[open]>summary{{margin-bottom:.75rem}}
details details{{border-top:1px solid var(--line);padding:.6rem 0 0;margin-top:.6rem}}
details details>summary{{color:var(--text);letter-spacing:1px}}
pre{{overflow-x:auto;max-width:100%;margin:.35rem 0 .75rem;padding:.6rem .75rem;background:var(--bg);border:1px solid var(--line);font:.8rem/1.45 {MONO}}}
pre code{{overflow-wrap:normal;white-space:pre}}
.api p,.api ul{{margin:.3rem 0}}
@media(max-width:600px){{
main{{padding:1.25rem .75rem 2rem}}
.frame{{padding:1.25rem .75rem}}
section{{padding:.9rem .75rem}}
h1{{font-size:clamp(1.3rem,5.5vw,1.6rem)}}
.sub{{font-size:.78rem}}
.facts{{grid-template-columns:repeat(auto-fit,minmax(min(100%,8rem),1fr));gap:.75rem}}
.production-lamp{{width:2.5rem;height:2.5rem}}
.production-clients li{{padding-left:4.6rem;min-height:6.5rem}}
.production-clients li::before{{left:.4rem;width:3.7rem;height:5.8rem}}
.scouter-alert{{padding:.5rem;gap:.5rem;font-size:.68rem;letter-spacing:.5px}}
.row .btn{{flex:1 0 auto}}
}}
'''

GUARDIAN_AURA = '''<svg class="guardian-aura" viewBox="0 0 160 320" shape-rendering="crispEdges"><path d="M80 8h8v24h8v-8h8v32h8v-12h8v40h8V68h8v48h8v-16h8v72h8v80h-8v24h-16v16H32v-16H16v-24H8v-80h8v-72h8v16h8V68h8v16h8V44h8v12h8V24h8v8h8z" fill="currentColor" fill-opacity=".07" stroke="currentColor" stroke-width="2" stroke-opacity=".26"/></svg>'''
MENTOR_AURA = '''<svg class="guardian-aura" viewBox="0 0 160 320"><ellipse cx="80" cy="175" rx="72" ry="132" fill="currentColor" fill-opacity=".04" stroke="currentColor" stroke-width="1.5" stroke-opacity=".2"/><ellipse cx="80" cy="175" rx="66" ry="124" fill="none" stroke="currentColor" stroke-width="1" stroke-opacity=".12"/></svg>'''


def _guardians():
    sparks = '<span class="guardian-sparks"><i></i><i></i><i></i><i></i><i></i></span>'
    figures = ''.join(f'''<figure class="guardian guardian-{side}"><div class="guardian-stage"><div class="guardian-glow"></div>{aura}<div class="guardian-entry"><img class="guardian-image" src="/assets/{sprite}-sidebar.png" alt=""></div>{sparks}</div><figcaption>{label}</figcaption></figure>'''
                      for side, sprite, label, aura in [('goku', 'goku', 'GOKU', GUARDIAN_AURA), ('kai', 'king-kai', 'KING KAI', MENTOR_AURA), ('frieza', 'frieza', 'FRIEZA', GUARDIAN_AURA)])
    return f'<aside class="lab-guardians" aria-hidden="true">{figures}</aside>'


# Decorative vector effects stay separate from the pixel sprites so their
# outlines and impact points scale together on narrow screens.
NAMEK_SHIELD = '''
<svg class="namek-shield" viewBox="0 0 180 180" shape-rendering="crispEdges">
<defs>
<path id="namek-field-shape" d="M8 160V128h4v-24h4V84h8V64h8V48h12V32h12V20h12V12h12V8h20v4h12v8h12v12h12v16h12v16h8v20h8v20h4v24h4v32h-8v8h-20v4H36v-4H16v-8z"/>
<clipPath id="namek-field-clip"><use href="#namek-field-shape"/></clipPath>
<radialGradient id="namek-field-fill" cx="60%" cy="35%" r="75%"><stop stop-color="#cafff5" stop-opacity=".01"/><stop offset=".65" stop-color="#57eebd" stop-opacity=".025"/><stop offset="1" stop-color="#7cfde2" stop-opacity=".17"/></radialGradient>
<linearGradient id="namek-field-rim" x1="0%" y1="100%" x2="100%" y2="0%"><stop stop-color="#3dbea4" stop-opacity=".6"/><stop offset=".55" stop-color="#83f9d8"/><stop offset="1" stop-color="#e8fffa"/></linearGradient>
<pattern id="namek-field-grid" width="24" height="22" patternUnits="userSpaceOnUse"><path d="M12 1 22 6v10l-10 5-10-5V6z" fill="none" stroke="#96ffe2" stroke-width=".7"/></pattern>
</defs>
<use href="#namek-field-shape" fill="url(#namek-field-fill)"/>
<rect width="180" height="180" fill="url(#namek-field-grid)" opacity=".13" clip-path="url(#namek-field-clip)"/>
<use href="#namek-field-shape" fill="none" stroke="url(#namek-field-rim)" stroke-width="2"/>
<use href="#namek-field-shape" fill="none" stroke="#7feee1" stroke-width="1" opacity=".4" transform="translate(90 90) scale(.95) translate(-90 -90)"/>
<path d="M36 70V56h12V40h14V28h16" fill="none" stroke="#e1fff6" stroke-width="2" opacity=".55"/>
<ellipse cx="90" cy="166" rx="77" ry="4" fill="none" stroke="#8effdc" stroke-width="1" opacity=".45"/>
<path class="namek-shield-hit" d="M148 64h8v20h8v20h4v24" fill="none" stroke="#edffff" stroke-width="3"/>
<path class="namek-shield-hit namek-hit-second" d="M148 64h8v20h8v20h4v24" fill="none" stroke="#edffff" stroke-width="3"/>
<path class="namek-shield-hit namek-hit-third" d="M148 64h8v20h8v20h4v24" fill="none" stroke="#edffff" stroke-width="3"/>
</svg>'''
NAMEK_IMPACT = '''<svg class="namek-impact" viewBox="0 0 32 32" shape-rendering="crispEdges"><path d="M14 9h4v5h5v4h-5v5h-4v-5H9v-4h5z" fill="#f3ffff"/><path d="M14 1h4v5h-4zM14 26h4v5h-4zM1 14h5v4H1zM26 14h5v4h-5zM4 4h4v4H4zM24 4h4v4h-4zM4 24h4v4H4zM24 24h4v4h-4z" fill="currentColor"/><path d="M11 5h10v3h3v3h3v10h-3v3h-3v3H11v-3H8v-3H5V11h3V8h3z" fill="none" stroke="currentColor" stroke-width="1" opacity=".6"/></svg>'''

BANNER = f'''<figure class="namek-banner"><img class="namek-landscape" src="/assets/namek-banner.jpg" alt="Pixel art panorama of Planet Namek with green sky, turquoise water, blue trees and three suns">
<div class="namek-battle" aria-hidden="true"><div class="namek-pod"><div class="namek-pod-entry"><img src="/assets/frieza-pod.png" alt=""></div></div>
<div class="namek-defense"><img class="namek-outpost" src="/assets/namek-outpost.png" alt=""><img class="namek-defender" src="/assets/goku-guard.png" alt="">{NAMEK_SHIELD}<span class="namek-palm"></span></div>
<div class="namek-shots"><span class="namek-shot"></span><span class="namek-shot"></span><span class="namek-shot"></span></div><div class="namek-impacts">{NAMEK_IMPACT * 3}</div></div>
<figcaption>Planet Namek</figcaption></figure>'''

INDICATOR = '''
<svg class="indicator-gray" viewBox="0 0 48 48"><circle cx="24" cy="24" r="18" fill="#93969d" stroke="#f7f5f0" stroke-width="2"/><path d="M19 18a5 5 0 0 1 10 0c0 4-5 4-5 8" fill="none" stroke="#0b0a0d" stroke-width="3"/><rect x="22.5" y="31" width="3" height="3" fill="#0b0a0d"/></svg>
<svg class="indicator-red" viewBox="0 0 48 48"><path d="M14 3h20l11 11v20L34 45H14L3 34V14z" fill="#ef5350" stroke="#f7f5f0" stroke-width="2"/><path d="M24 12v17" stroke="#0b0a0d" stroke-width="5"/><rect x="21.5" y="34" width="5" height="5" fill="#0b0a0d"/></svg>
<svg class="indicator-yellow" viewBox="0 0 48 48"><path d="M24 2 46 24 24 46 2 24z" fill="#f5cc47" stroke="#f7f5f0" stroke-width="2"/><path d="M24 12v18" stroke="#0b0a0d" stroke-width="5"/><rect x="21.5" y="34" width="5" height="5" fill="#0b0a0d"/></svg>
<svg class="indicator-green" viewBox="0 0 48 48"><path d="M24 3 41 9v15c0 10-7 17-17 21C14 41 7 34 7 24V9z" fill="#43c78a" stroke="#f7f5f0" stroke-width="2"/><path d="m15 24 6 6 12-13" fill="none" stroke="#0b0a0d" stroke-width="4" stroke-linecap="square" stroke-linejoin="miter"/></svg>
'''


def _phases():
    cards = ''.join(f'''<div class="phase" data-phase="{phase}"><div class="phase-name">{phase}<span class="phase-now">current</span><span class="phase-done">&#10004; done</span></div>
<p>{escape(goal)}</p><button class="btn ghost" type="button" data-start="{phase}">Start {phase}</button></div>''' for phase, goal in GOALS.items())
    return f'''<div class="phases">{cards}</div>
<div class="row"><button class="btn" type="button" id="replay">Replay current phase</button><button class="btn ghost" type="button" id="stop">Stop scenario</button></div>
<p class="hint">Start or Replay clears every block, issues a new run ID and replays the scenario traffic. Completed phases stay marked.</p>
<p id="notice" class="notice" role="status" aria-live="polite"></p>'''


def _solutions():
    links = ''.join(f'<a class="btn ghost" href="/workflows/{phase}.json" download="romhack-{phase}.json">{phase}</a>' for phase in PHASES)
    return f'<div class="row">{links}</div><p class="hint">Stuck? Import the solution into n8n (&#8943; menu &rarr; Import from File), then publish it.</p>'


def _json(value):
    return f'<pre><code>{escape(json.dumps(value, indent=2))}</code></pre>'


def _endpoint(method, path):
    return f'<pre><code>{escape(method)} {API_BASE}{escape(path)}</code></pre>'


def _fields(items):
    return '<ul>' + ''.join(f'<li><code>{escape(name)}</code> &mdash; {text}</li>' for name, text in items) + '</ul>'


SEARCHES = (
    ('Timeline of one source', 'search index=romhack run_id="<run_id>" src_ip="<ip>"\n| dedup event_id\n| sort 0 _time\n| table _time src_ip path status auth_outcome application_event synthetic_user synthetic_session'),
    ('Traffic per source', 'search index=romhack run_id="<run_id>" sourcetype=romhack:web\n| dedup event_id\n| stats count by src_ip status'),
    ('WAF decisions', 'search index=romhack run_id="<run_id>" sourcetype=romhack:waf\n| stats count by src_ip action'),
    ('Audit trail', 'search index=romhack run_id="<run_id>" sourcetype=romhack:audit\n| sort - _time\n| table _time kind decision reasoning'),
)


def _api_reference():
    """Request contracts for the services your workflow calls; no phase solutions."""
    services = {
        'Incoming alert': f'''<p>The workshop posts each alert to your n8n <strong>Webhook</strong> trigger: method <code>POST</code>, path <code>romhack</code>. The payload is at <code>$json.body</code>:</p>
{_json({"run_id": "<run id>", "event_id": "<stable detection id>", "src_ip": "<source ip>", "scenario": "<detection name>", "count": "<matching events>"})}
<p>Alerts go to the production URL <code>/webhook/romhack</code>, which exists only while the workflow is <strong>published (active)</strong>. Saving alone is not enough: until you publish, the Alerts table shows <em>workflow not published</em> and retries.</p>
<p>Each HTTP Request node replaces the current item with its response, so reference alert fields explicitly, e.g. <code>{{{{ $('Webhook').first().json.body.src_ip }}}}</code> (use your trigger node's name).</p>''',
        'Remediation (WAF)': f'''{_endpoint('POST', '/api/remediations')}
{_json({"action": "block", "src_ip": "<ip>", "run_id": "<run id>", "idempotency_key": "<unique per decision>"})}
<p><code>action</code> is <code>block</code> or <code>unblock</code>; <code>run_id</code> must be the current run. Repeating a request with the same key returns the same operation; reusing a key for a different action is rejected. In C3 only, add <code>"ttl_seconds"</code> (10&ndash;600) to a block to make it expire by itself.</p>
<p>Remediation is asynchronous: the response is an operation, not an applied block. Follow it with</p>{_endpoint('GET', '/api/operations/<operation id>')}
{_fields([("queued", "accepted, waiting for the WAF"), ("applied", "WAF rule updated"), ("observed", "enforcement verified on live traffic")])}''',
        'Threat intelligence': f'''{_endpoint('GET', '/api/intelligence/reputation?ip=<ip>')}
{_fields([("score", "historical abuse score, 0&ndash;100"), ("reports", "number of abuse reports"), ("report_context", "optional note from the provider")])}
{_endpoint('GET', '/api/intelligence/context?ip=<ip>')}
{_fields([("network", "network description"), ("scanner", "known scanner (boolean)"), ("shared_nat", "shared egress address (boolean)")])}
<p>Both responses include <code>ip</code>, <code>simulated</code> and <code>status</code>: <code>ok</code>, or <code>unknown</code> for an address the provider has no data on. HTTP 503 means the service is unavailable. The data is simulated.</p>''',
        'Splunk search': f'''{_endpoint('POST', '/api/search')}
{_json({"search": "search index=romhack <your SPL>", "run_id": "<run id>"})}
<p>Returns <code>{{"results": [...], "truncated": false}}</code>. Runs as a read-only Splunk user over the last 15 minutes and only sees the <code>run_id</code> you send, so you never type it into the SPL. At most 50 rows; larger results are cut and <code>truncated</code> is true. A leading <code>search</code> is optional.</p>
<p>Index <code>romhack</code>; sourcetypes <code>romhack:web</code> (application access), <code>romhack:waf</code> (WAF decisions) and <code>romhack:audit</code> (your audit records).</p>
{''.join(f'<h3>{escape(title)}</h3><pre><code>{escape(spl)}</code></pre>' for title, spl in SEARCHES)}''',
        'Audit': f'''{_endpoint('POST', '/api/audit')}
{_json({"run_id": "<run id>", "event_id": "<alert event_id>", "kind": "<step>", "decision": "<decision>", "reasoning": "<text>", "evidence": ["<fact>"]})}
<p>Indexed as <code>romhack:audit</code>, once per <code>event_id</code> and <code>kind</code>. A <code>decision</code> of <code>allow</code> records that a client was deliberately left unblocked. Reasoning up to 4000 characters and evidence up to 20 items of 1000 characters; longer values are clipped.</p>''',
        'Approvals': f'''{_endpoint('POST', '/api/approvals')}
{_json({"url": "{{ $execution.resumeFormUrl }}", "run_id": "<run id>", "src_ip": "<ip>"})}
<p>Registers the n8n waiting form of a Wait node (resume <em>On form submitted</em>) so it appears under Approvals on this page. Once the form is submitted, record the outcome:</p>
{_endpoint('POST', '/api/approvals/<approval id>/validate')}<p>Consumes an approval; it succeeds only once.</p>
{_endpoint('POST', '/api/approvals/<approval id>/deny')}<p>Records a decline.</p>''',
    }
    groups = ''.join(f'<details><summary>{escape(name)}</summary>{html}</details>' for name, html in services.items())
    return f'<p>Call these from n8n HTTP Request nodes at <code>{API_BASE}</code> (the workshop\'s address inside Docker). No authentication or credentials are needed. Replace <code>&lt;...&gt;</code> placeholders with expressions; never paste them literally.</p>{groups}'


SCRIPT = '''
(() => {
  const $ = id => document.getElementById(id);
  const GOOD = new Set(['delivered', 'applied', 'observed', 'approved', 'ready']);
  const BAD = new Set(['retry', 'failed', 'stale']);
  // Builds elements from strings as text nodes: workshop data never becomes markup.
  const h = (tag, props, ...kids) => {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === undefined || value === null || value === false) continue;
      key === 'class' ? el.className = value : el.setAttribute(key, value === true ? '' : value);
    }
    el.append(...kids.flat().filter(kid => kid !== undefined && kid !== null && kid !== false && kid !== '').map(kid => kid instanceof Node ? kid : String(kid)));
    return el;
  };
  const time = t => t ? new Date(t * 1000).toLocaleTimeString([], {hour12: false}) : '';
  const badge = status => h('span', {class: 'badge' + (GOOD.has(status) ? ' good' : BAD.has(status) ? ' bad' : '')}, status || 'unknown');
  const table = (headers, rows, empty) => rows.length
    ? h('div', {class: 'scroll'}, h('table', {}, h('thead', {}, h('tr', {}, headers.map(text => h('th', {}, text)))),
        h('tbody', {}, rows.map(row => h('tr', {}, row.map(cell => h('td', {}, cell)))))))
    : h('p', {class: 'empty'}, empty);
  const safeUrl = url => { try { const parsed = new URL(url); return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : null; } catch (_) { return null; } };
  // Re-render a region only when its data changed, so focus and selection survive polls.
  const seen = {};
  const put = (id, data, build) => {
    const key = JSON.stringify(data);
    if (seen[id] === key) return;
    seen[id] = key;
    $(id).replaceChildren(...[].concat(build(data)).filter(Boolean));
  };

  const LINES = {
    gray: ["I can't tell who's getting through right now.", "No fresh readings, Goku. Start a phase and wait for evidence before calling it safe."],
    yellow: ["He's getting through! Let's check the evidence before we strike.", "My, my... your defenses are letting me right in."],
    red: ["Wait! We've shut out someone we're supposed to protect!", "Easy, Goku! A block is no victory if innocent people lose access."],
    green: ["Frieza's blocked. Everyone we're protecting can still get through!", "Now that's control, Goku! Keep watching the evidence."],
  };
  const PHASE_LINES = {
    B: {yellow: ["I'll hold him off. Let's check the reputation signals!", "A score? How charming. I'm still reaching your app."],
        green: ["Frieza's stopped, and the Namek citizen still has access!", "Good! Reputation helped separate these two alerts."]},
    C1: {red: ["One of our friends is locked out! Could it be the VPN?", "A high score isn't the whole story. Investigate that VPN, Goku!"],
         green: ["Frieza's blocked. Piccolo and the others can still connect!", "Context matters! Investigate first, then choose the target."]},
    C2: {yellow: ["He's still getting through. Let's check the approval outcome.", "No block in my way? I'll make myself quite comfortable."],
         green: ["Frieza's blocked, and our friends still have access!", "Check Chi-Chi's approval alongside the observed block, Goku."]},
    C3: {yellow: ["He's getting through. Let's check the temporary block.", "Your timer won't help until your defense actually stops me."]},
  };
  function dialogue(state) {
    const color = state.production.color;
    const lines = {...LINES, ...(PHASE_LINES[state.phase] || {})};
    const attacker = (state.production.clients.find(client => client.attacker) || {}).ip;
    const ops = state.operations.filter(op => op.src_ip === attacker && op.status === 'observed').sort((a, b) => (a.completed_at || 0) - (b.completed_at || 0));
    const lastBlock = [...ops].reverse().find(op => op.action === 'block');
    if (state.phase === 'C3' && lastBlock && lastBlock.ttl_seconds) {
      lines.green = ["The temporary block is holding. Our friends can still connect!", "Watch the timer, Goku! This protection has an expiry."];
      if (ops[ops.length - 1].action === 'unblock') lines.yellow = ["The temporary defense was lifted. He's getting through again!", "Did you think that little timed defense would keep me away forever?"];
    }
    const waiting = state.approvals.length > 0;
    if (waiting) lines.yellow = ["I'm ready! But we're waiting for Chi-Chi's decision.", "Patience, Goku! A proposal isn't permission. Frieza still has access."];
    const other = color === 'yellow' && !waiting ? 'Frieza' : 'King Kai';
    $('dialogue').dataset.speaker = other.toLowerCase().replace(' ', '-');
    put('dialogue', [color, other, lines[color] || lines.gray], ([, who, said]) => h('div', {class: 'manga-exchange'},
      ['Goku', who].map((name, i) => h('p', {class: 'manga-balloon', 'data-character': name}, h('strong', {}, name.toUpperCase()), said[i]))));
  }

  function render(state) {
    const names = Object.fromEntries(state.production.clients.map(client => [client.ip, client.name]));
    const who = ip => [h('code', {}, ip), names[ip] && h('small', {}, names[ip])];
    $('run-phase').textContent = state.phase;
    $('run-id').textContent = state.run_id ? state.run_id.slice(0, 8) : '\\u2014';
    $('run-id').title = state.run_id || '';
    put('run-status', state.running, running => badge(running ? 'running' : 'stopped'));
    for (const card of document.querySelectorAll('.phase')) {
      const phase = card.dataset.phase;
      card.toggleAttribute('data-current', phase === state.phase && Boolean(state.run_id));
      card.toggleAttribute('data-done', state.completed.includes(phase));
      card.querySelector('button').textContent = (phase === state.phase && state.running ? 'Restart ' : 'Start ') + phase;
    }

    const production = state.production;
    $('production').dataset.color = production.color;
    $('production-label').textContent = production.label;
    $('production-reason').textContent = production.reason;
    put('production-clients', production.clients, clients => clients.map(client => h('li', {'data-connectivity': client.connectivity},
      h('strong', {}, client.name + ': ' + client.connectivity),
      h('small', {}, client.ip + ' \\u00b7 ' + client.role),
      h('small', {}, client.attacker ? 'Attacker' : 'Legitimate client'))));
    put('production-errors', production.evidence_errors || [], errors => errors.map(error => h('p', {class: 'production-error'}, 'Scenario evidence: ' + error)));
    dialogue(state);

    put('checklist', [state.phase, state.checklist], ([phase, items]) => items.length
      ? [h('p', {class: 'hint'}, 'Phase ' + phase + ' is complete once every required step is done.'),
         h('ul', {class: 'checklist'}, items.map(item => h('li', {'data-done': item.done}, item.label, item.required && h('small', {}, 'required'))))]
      : h('p', {class: 'empty'}, 'Start a phase to see its checklist.'));

    put('approvals', state.approvals, approvals => approvals.length
      ? h('ul', {class: 'approvals'}, approvals.map(approval => {
          const url = safeUrl(approval.url);
          return h('li', {}, h('span', {}, 'Block ', h('code', {}, approval.src_ip), names[approval.src_ip] ? ' (' + names[approval.src_ip] + ')' : '', ' \\u00b7 requested ' + time(approval.created_at)),
            url ? h('a', {class: 'btn', href: url, target: '_blank', rel: 'noopener noreferrer'}, 'Open approval form \\u2197') : h('span', {class: 'error'}, 'Invalid form link'));
        }))
      : h('p', {class: 'empty'}, 'No pending approvals. In C2 and C3 your workflow registers one here before blocking.'));

    put('alerts', state.alerts, alerts => {
      const failing = alerts.find(alert => alert.status === 'retry');
      const callout = failing && h('div', {class: 'callout', role: 'alert'}, h('strong', {}, 'Alerts are not reaching n8n'),
        h('p', {}, failing.last_error || 'Delivery failed; retrying.'),
        h('p', {}, /not published/.test(failing.last_error || '')
          ? 'Open your workflow in n8n and publish (activate) it. The workshop keeps retrying, so the alert arrives as soon as the workflow is live.'
          : 'Check that n8n is running and the Webhook node uses method POST and path romhack. The workshop keeps retrying.'));
      const delivery = alert => [badge(alert.status),
        alert.evidence_status === 'waiting' && h('small', {}, 'waiting for Splunk to index the evidence'),
        alert.status === 'retry' && h('small', {class: 'error'}, alert.last_error + ' (attempt ' + alert.attempts + ')')];
      return [callout, table(['Time', 'Source', 'Scenario', 'Count', 'Delivery'],
        alerts.map(alert => [time(alert.created_at), who(alert.src_ip), alert.scenario, alert.count, delivery(alert)]),
        state.running ? 'No alerts yet. Splunk raises them about a minute after the scenario starts.' : 'No alerts. Start a phase to replay the scenario.')];
    });

    put('operations', state.operations, ops => table(['Time', 'Action', 'Source', 'TTL', 'Status'],
      ops.map(op => [time(op.completed_at || op.created_at), op.action, who(op.src_ip),
        op.ttl_seconds && [op.ttl_seconds + 's', op.expires_at && h('small', {'data-expires': op.expires_at})], badge(op.status)]),
      'No remediation requests in this run.'));
    tick();
  }

  // Temporary blocks count down between polls; expires_at is null until the block is observed.
  function tick() {
    for (const el of document.querySelectorAll('[data-expires]')) {
      const left = Math.round(Number(el.dataset.expires) - Date.now() / 1000);
      el.textContent = left > 0 ? 'expires in ' + left + 's' : 'expired, unblocking';
    }
  }
  setInterval(tick, 1000);

  let timer;
  async function refresh() {
    clearTimeout(timer);
    try {
      const response = await fetch('/api/state', {cache: 'no-store', signal: AbortSignal.timeout(4000)});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      render(await response.json());
      $('live').textContent = 'Live \\u00b7 updated ' + new Date().toLocaleTimeString([], {hour12: false});
    } catch (_) {
      $('live').textContent = 'Workshop unreachable; retrying. Is the workshop container running?';
    }
    timer = setTimeout(refresh, 3000);
  }

  const notice = (text, error) => { $('notice').textContent = text; $('notice').toggleAttribute('data-error', Boolean(error)); };
  async function post(path, body, done) {
    const buttons = document.querySelectorAll('button');
    buttons.forEach(button => { button.disabled = true; });
    try {
      const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Request failed (HTTP ' + response.status + ')');
      notice(done(data));
    } catch (error) {
      notice(error.message, true);
    } finally {
      buttons.forEach(button => { button.disabled = false; });
      refresh();
    }
  }
  const started = data => 'Phase ' + data.phase + ' started \\u00b7 run ' + data.run_id.slice(0, 8) + '. Blocks cleared; scenario replaying.';
  document.querySelectorAll('[data-start]').forEach(button => button.addEventListener('click', () => post('/api/start', {phase: button.dataset.start}, started)));
  $('replay').addEventListener('click', () => post('/api/replay', {}, started));
  $('stop').addEventListener('click', () => post('/api/stop', {}, () => 'Scenario traffic stopped.'));
  refresh();
})();
'''


def render(config):
    """Return the portal shell; live data arrives through /api/state and is rendered as text."""
    password = escape(config['splunk_admin_password'])
    link = lambda key: f'<a href="{escape(config[key])}" target="_blank" rel="noopener">{escape(config[key])}</a>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RomHack · Keep caLLM and Let It Block</title><style>{CSS}</style></head>
<body>{_guardians()}<main><div class="frame">
<header><div class="mark"><span>ROM</span>HACK</div><p class="kicker">Camp 2026 / Workshop</p><h1>Keep caLLM <span>and Let It Block</span></h1><p class="sub">Agentic SOAR with n8n + Splunk</p></header>
{BANNER}
<aside id="dialogue" class="manga-dialogue" aria-label="Scene dialogue"></aside>
<section><h2>Lab</h2>
<div class="facts"><div><span class="label">Phase</span><span id="run-phase">&mdash;</span></div><div><span class="label">Run</span><code id="run-id">&mdash;</code></div><div><span class="label">Scenario</span><span id="run-status"><span class="badge">loading</span></span></div></div>
<div class="facts"><div><span class="label">n8n</span>{link('n8n_public_url')}</div><div><span class="label">Splunk</span>{link('splunk_public_url')}<small class="login">login <code>admin</code> / <code>{password}</code></small></div><div><span class="label">Website</span>{link('target_public_url')}</div></div>
<p id="live" class="live" aria-live="off">Connecting&hellip;</p><noscript><p class="live">This page needs JavaScript.</p></noscript></section>
<section id="production" class="production" data-color="gray" aria-label="Production access">
<div class="production-heading"><span class="production-lamp" aria-hidden="true">{INDICATOR}</span><h2 id="production-label" aria-live="polite">Production access unknown</h2></div>
<div class="scouter-alert" aria-hidden="true"><span class="scouter-screen"></span><span>Scouter alert / Frieza in range</span></div>
<p id="production-reason"></p><ul id="production-clients" class="production-clients"></ul>
<p class="hint">Observed access through the website for each scenario client, sampled every few seconds. It shows what really happened, not what your workflow intended.</p>
<div id="production-errors" role="status"></div></section>
<section><h2>Phases</h2>{_phases()}</section>
<section><h2>Checklist</h2><div id="checklist"></div></section>
<section><h2>Approvals</h2><div id="approvals"></div></section>
<section><h2>Alerts</h2><div id="alerts"></div></section>
<section><h2>Remediation operations</h2><div id="operations"></div></section>
<section><h2>Solutions</h2>{_solutions()}</section>
<section class="api"><details id="api-reference"><summary>API reference</summary>{_api_reference()}</details></section>
</div></main><script>{SCRIPT}</script></body></html>'''
