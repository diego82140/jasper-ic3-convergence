"""Complete declared adapter signatures; native ABI qualification is separate."""
import collections,json,re,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BUILDS={
 'prerelease':'b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604',
 'production':'b3e7723c4335266b1cd1436277111d54ee7802944b8b4f7d6eaacaa28b7c84b4',
 'production-p001':'e1b53cf546e048df0f9996646afba34b0faf7b38095b22ed700a507b64cf4e7b'}

def declared_signature(text):
    lines=text.splitlines();assert lines.pop(0)=='JIPSTATS_EVENTS 1'
    metadata={};hooks=[]
    for line in lines:
        p=line.split()
        if p[0]=='hook':
            assert len(p)==10 and re.fullmatch(r'(?:[0-9a-f]{2}){1,32}',p[-1])
            hooks.append((p[1],int(p[2],16),list(map(int,p[3:9]))))
        else:
            assert p[0] not in metadata;metadata[p[0]]=p[1:]
    assert set(metadata)=={'sha256','callback','fields','cube','relative_results','solver_results','proof_results','details'}
    assert len({rva for _,rva,_ in hooks})==len(hooks)
    before={rva:i for i,(_,rva,_) in enumerate(h for h in hooks if h[0]=='satbefore')}
    after=collections.Counter(roles[-1] for k,_,roles in hooks if k=='satafter')
    assert after==collections.Counter({rva:1 for rva in before})
    signature=[]
    for kind,rva,roles in hooks:
        if kind=='satafter':roles[-1]=before[roles[-1]]
        signature.append((kind,roles))
    metadata.pop('sha256')
    return metadata,signature

class DeclaredInterfaceParity(unittest.TestCase):
    def test_every_header_and_all_sixty_hook_roles_match(self):
        signatures=[declared_signature((ROOT/'profiles'/(sha+'.events')).read_text()) for sha in BUILDS.values()]
        self.assertEqual(len(signatures[0][1]),60)
        for actual in signatures[1:]:self.assertEqual(signatures[0],actual)
    def test_no_missing_hook_or_changed_field_is_hidden(self):
        text=(ROOT/'profiles'/(BUILDS['production']+'.events')).read_text()
        original=declared_signature(text)
        for changed in (text.replace('fields 200','fields 204'),
                        text.replace('cube 0 8 4','cube 0 12 4'),
                        '\n'.join(l for l in text.splitlines() if not l.startswith('hook getcex '))):
            self.assertNotEqual(original,declared_signature(changed))
    def test_every_september_build_has_all_helper_roles_and_displays(self):
        source=(ROOT/'source/src/parity.h').read_text()
        entries=dict((m[0],m[1:]) for m in re.findall(r'\{"([0-9a-f]{64})",(true|false),([^}]+)\}',source))
        for sha in BUILDS.values():
            enabled,raw=entries[sha];values=[int(v,0) for v in raw.split(',')]
            self.assertEqual(enabled,'true');self.assertEqual(len(values),6);self.assertTrue(all(values))
            text=(ROOT/'profiles'/(sha+'.events')).read_text()
            hooks=[p.split() for p in text.splitlines() if p.startswith('hook ')]
            by_kind=collections.defaultdict(set)
            for p in hooks:by_kind[p[1]].add(int(p[2],16))
            self.assertIn(values[2],by_kind['frontremove'])
            self.assertIn(values[4],by_kind['satafter']);self.assertIn(values[5],by_kind['satafter'])
    def test_production_helper_constants_match_the_reviewed_metadata(self):
        source=(ROOT/'source/src/parity.h').read_text()
        entries={m[0]:[int(v,0) for v in m[1].split(',')] for m in re.findall(r'\{"([0-9a-f]{64})",true,([^}]+)\}',source)}
        keys=('isinitial_return','pending_front_entry','pending_front_return','validation_step_after','validation_property_after')
        for label in ('production','production-p001'):
            sha=BUILDS[label];meta=json.loads((ROOT/'profiles'/(sha+'.json')).read_text());values=entries[sha]
            self.assertEqual(values[1:],[int(meta['helper_layout'][key],16) for key in keys])
            self.assertTrue(meta['formula_global_references'])
            self.assertTrue(all(int(ref['target'],16)==values[0] for ref in meta['formula_global_references']))

if __name__=='__main__':unittest.main()
