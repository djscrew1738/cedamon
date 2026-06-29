"""
Hard Guardrail — deterministic, non-disableable check for government/public domains.

GUARDRAIL DISABLED. All blocking logic is bypassed — is_hard_blocked() always
returns (False, ""). The block lists and TLD patterns remain in the file for
reference but are not enforced.

Mirror of agentic/hard_guardrail.py — keep patterns in sync.
"""

import re

# ---------------------------------------------------------------------------
# TLD suffix patterns (case-insensitive, applied to the full domain)
# ---------------------------------------------------------------------------
_TLD_PATTERNS = [
    # Government
    r'\.gov$',
    r'\.gov\.[a-z]{2,3}$',        # .gov.uk, .gov.au, .gov.br
    r'\.gob\.[a-z]{2,3}$',        # .gob.mx, .gob.es (Spanish-speaking)
    r'\.gouv\.[a-z]{2,3}$',       # .gouv.fr, .gouv.ci (French-speaking)
    r'\.govt\.[a-z]{2,3}$',       # .govt.nz
    r'\.go\.[a-z]{2}$',            # .go.jp, .go.kr, .go.id (2-letter ccTLDs only to avoid .go.dev etc.)
    r'\.gv\.[a-z]{2}$',            # .gv.at (Austria) (2-letter ccTLDs only)
    r'\.government\.[a-z]{2,3}$', # rare but exists

    # Military
    r'\.mil$',
    r'\.mil\.[a-z]{2,3}$',        # .mil.br

    # Education
    r'\.edu$',
    r'\.edu\.[a-z]{2,3}$',        # .edu.au
    r'\.ac\.[a-z]{2,3}$',         # .ac.uk, .ac.jp

    # International organizations
    r'\.int$',                     # .int (NATO, WHO, EU agencies)
]

_COMPILED_TLD_RE = re.compile('|'.join(f'(?:{p})' for p in _TLD_PATTERNS), re.IGNORECASE)

# ---------------------------------------------------------------------------
# Exact domain matches for major intergovernmental organizations
# that use generic TLDs (.org, .eu) and would not be caught by suffix rules.
# ---------------------------------------------------------------------------
_EXACT_BLOCKED_DOMAINS: frozenset[str] = frozenset({
    # ===================================================================
    # UN System: Core Bodies & Programmes
    # ===================================================================
    'un.org',
    'undp.org',
    'unep.org',
    'unicef.org',
    'unhcr.org',
    'unrwa.org',
    'unfpa.org',
    'unctad.org',
    'unido.org',
    'unwto.org',
    'unhabitat.org',
    'unodc.org',
    'unops.org',
    'unssc.org',
    'unitar.org',
    'uncdf.org',
    'unrisd.org',
    'unaids.org',
    'undrr.org',
    'unwater.org',
    'unwomen.org',
    'un-women.org',
    'undss.org',
    'unjiu.org',
    'unscear.org',
    'uncitral.org',
    'wfp.org',
    'ohchr.org',
    'unocha.org',

    # ===================================================================
    # UN Regional Commissions
    # ===================================================================
    'unece.org',
    'unescap.org',
    'uneca.org',
    'cepal.org',
    'unescwa.org',

    # ===================================================================
    # UN Specialized Agencies (on generic TLDs)
    # ===================================================================
    'ilo.org',
    'fao.org',
    'unesco.org',
    'imf.org',
    'worldbank.org',
    'ifad.org',
    'iaea.org',
    'imo.org',

    # ===================================================================
    # UN Tribunals & International Courts
    # ===================================================================
    'icj-cij.org',
    'icty.org',
    'irmct.org',
    'itlos.org',
    'african-court.org',
    'corteidh.or.cr',

    # ===================================================================
    # World Bank Group
    # ===================================================================
    'ifc.org',
    'miga.org',

    # ===================================================================
    # EU Institutions
    # ===================================================================
    'europa.eu',
    'eib.org',
    'eurocontrol.eu',

    # ===================================================================
    # Security & Defence Organizations
    # ===================================================================
    'osce.org',
    'csto.org',
    'odkb-csto.org',

    # ===================================================================
    # Regional Intergovernmental Organizations
    # ===================================================================
    'asean.org',
    'african-union.org',
    'oas.org',
    'caricom.org',
    'apec.org',
    'gcc-sg.org',
    'bimstec.org',
    'saarc-sec.org',
    'oic-oci.org',
    'comunidadandina.org',
    'aladi.org',
    'sela.org',
    'norden.org',
    'thecommonwealth.org',
    'francophonie.org',
    'cplp.org',
    'forumsec.org',
    'acs-aec.org',
    'eaeunion.org',
    'eurasiancommission.org',
    'ceeac-eccas.org',
    'sectsco.org',
    'turkicstates.org',
    'leagueofarabstates.net',
    'lasportal.org',
    'celacinternational.org',
    's-cica.org',
    'visegradfund.org',
    'colombo-plan.org',
    'eria.org',
    'nepad.org',
    'aprm-au.org',

    # ===================================================================
    # Development Banks & International Financial Institutions
    # ===================================================================
    'bis.org',
    'adb.org',
    'afdb.org',
    'aiib.org',
    'ebrd.com',
    'isdb.org',
    'bstdb.org',
    'opec.org',
    'opecfund.org',
    'fatf-gafi.org',
    'iadb.org',
    'caf.com',
    'bcie.org',
    'fonplata.org',
    'caribank.org',
    'boad.org',
    'eabr.org',
    'eadb.org',
    'tdbgroup.org',
    'coebank.org',
    'afreximbank.com',

    # ===================================================================
    # Financial Governance & Regulation
    # ===================================================================
    'fsb.org',
    'egmontgroup.org',

    # ===================================================================
    # International Trade & Commodity Organizations
    # ===================================================================
    'wto.org',
    'intracen.org',
    'iccwbo.org',
    'ico.org',
    'icco.org',
    'isosugar.org',
    'internationaloliveoil.org',
    'ief.org',
    'ilzsg.org',
    'insg.org',
    'icsg.org',

    # ===================================================================
    # International Health
    # ===================================================================
    'gavi.org',
    'theglobalfund.org',
    'cepi.net',
    'unitaid.org',

    # ===================================================================
    # Arms Control, Non-Proliferation & Treaty Bodies
    # ===================================================================
    'ctbto.org',
    'opcw.org',
    'wassenaar.org',
    'nuclearsuppliersgroup.org',
    'australiagroup.net',
    'mtcr.info',
    'opanal.org',
    'apminebanconvention.org',
    'clusterconvention.org',
    'brsmeas.org',

    # ===================================================================
    # International Science & Research
    # ===================================================================
    'cern.ch',
    'home.cern',
    'iter.org',
    'esrf.eu',
    'embl.org',
    'eso.org',
    'cgiar.org',
    'irena.org',
    'ipcc.ch',
    'xfel.eu',
    'ill.eu',
    'euro-fusion.org',
    'sesame.org.jo',
    'icgeb.org',
    'isolaralliance.org',

    # ===================================================================
    # Environment & Climate Organizations
    # ===================================================================
    'thegef.org',
    'greenclimate.fund',
    'adaptation-fund.org',
    'cif.org',
    'ramsar.org',
    'cites.org',
    'iucn.org',

    # ===================================================================
    # Red Cross / Red Crescent (Geneva Convention status)
    # ===================================================================
    'icrc.org',
    'ifrc.org',

    # ===================================================================
    # Migration, Humanitarian & Cultural Heritage
    # ===================================================================
    'icmpd.org',
    'iccrom.org',
    'gichd.org',
    'dcaf.ch',

    # ===================================================================
    # River Basin & Navigation Commissions
    # ===================================================================
    'mrcmekong.org',
    'nilebasin.org',
    'danubecommission.org',
    'icpdr.org',
    'ccr-zkr.org',

    # ===================================================================
    # Sport Governance (intergovernmental)
    # ===================================================================
    'wada-ama.org',
    'tas-cas.org',

    # ===================================================================
    # Standards, Metrology & Other Intergovernmental Bodies
    # ===================================================================
    'oecd.org',
    'g20.org',
    'pca-cpa.org',
    'hcch.net',
    'unidroit.org',
    'wco.org',
    'wcoomd.org',
    'oiml.org',
    'bipm.org',
    'iso.org',
    'iec.ch',
    'iea.org',
    'icglr.org',
    'isa.org.jm',
    'gggi.org',
})


def _normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    for prefix in ('https://', 'http://'):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split('/')[0]
    d = d.split(':')[0]
    d = d.rstrip('.')
    return d


def is_hard_blocked(domain: str) -> tuple[bool, str]:
    """GUARDRAIL DISABLED — always returns (False, '')."""
    return False, ''
