import streamlit as st
import requests
import re
import time
import socket
from urllib.parse import urlparse, urljoin
from datetime import datetime
import ssl
import whois
from bs4 import BeautifulSoup
import hashlib
import json

# Page configuration
st.set_page_config(
    page_title="🛡️ Link Guard - URL Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        text-align: center;
        color: white;
        margin-bottom: 2rem;
    }
    .feature-card {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 4px solid #667eea;
        margin: 1rem 0;
        color: #333;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .feature-card h4 {
        color: #667eea;
        margin-bottom: 0.5rem;
        font-weight: 600;
    }
    .feature-card p {
        color: #666;
        line-height: 1.5;
        margin: 0;
    }
    .safe-result {
        background: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 1rem;
        color: #155724;
    }
    .warning-result {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 5px;
        padding: 1rem;
        color: #856404;
    }
    .danger-result {
        background: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 5px;
        padding: 1rem;
        color: #721c24;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

class LinkGuard:
    def __init__(self):
        self.suspicious_keywords = [
            'phishing', 'malware', 'virus', 'trojan', 'scam', 'fraud',
            'fake', 'suspicious', 'warning', 'alert', 'security',
            'click-here', 'urgent', 'verify', 'suspend', 'limited-time',
            'eicar', 'test-malware', 'exploit', 'payload', 'backdoor'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'short.link', 'is.gd', 'buff.ly'
        ]
        
        self.malware_domains = [
            'malware.wicar.org', 'eicar.org', 'malware-traffic-analysis.net',
            'hybrid-analysis.com', 'phishing-test.com', 'malwaredomainlist.com',
            'malc0de.com', 'urlvoid.com', 'virusshare.com'
        ]
        
        self.safe_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'stackoverflow.com', 'reddit.com', 'wikipedia.org'
        ]

    def validate_url(self, url):
        """Validate URL format"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            return parsed.netloc != '' and parsed.scheme in ['http', 'https']
        except:
            return False

    def check_url_accessibility(self, url):
        """Check if URL is accessible"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            return {
                'accessible': True,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'final_url': response.url,
                'redirects': len(response.history)
            }
        except requests.exceptions.RequestException as e:
            return {
                'accessible': False,
                'error': str(e),
                'status_code': None,
                'response_time': None,
                'final_url': None,
                'redirects': 0
            }

    def check_ssl_certificate(self, url):
        """Check SSL certificate validity"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return {'has_ssl': False, 'ssl_valid': False}
            
            hostname = parsed.hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    return {
                        'has_ssl': True,
                        'ssl_valid': True,
                        'expiry_date': expiry_date,
                        'issuer': cert.get('issuer', []),
                        'subject': cert.get('subject', [])
                    }
        except:
            return {'has_ssl': False, 'ssl_valid': False}

    def analyze_domain(self, url):
        """Analyze domain information"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check against known malware domains first
            domain_status = 'unknown'
            if any(malware_domain in domain for malware_domain in self.malware_domains):
                domain_status = 'malware'
            elif any(safe_domain in domain for safe_domain in self.safe_domains):
                domain_status = 'safe'
            elif any(sus_domain in domain for sus_domain in self.suspicious_domains):
                domain_status = 'suspicious'
            
            # Check for malware-related keywords in URL path
            full_url = url.lower()
            if any(keyword in full_url for keyword in ['eicar', 'malware', 'virus', 'trojan', 'exploit']):
                domain_status = 'malware'
            
            # Get domain info
            try:
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
            except:
                creation_date = None
            
            return {
                'domain': domain,
                'status': domain_status,
                'creation_date': creation_date,
                'is_shortener': domain_status == 'suspicious'
            }
        except:
            return {'domain': None, 'status': 'unknown', 'creation_date': None}

    def analyze_content(self, url):
        """Analyze webpage content for suspicious elements"""
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Get page title and meta description
            title = soup.find('title')
            title_text = title.text.strip() if title else ''
            
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            description = meta_desc.get('content', '') if meta_desc else ''
            
            # Check for suspicious keywords
            content_text = (title_text + ' ' + description).lower()
            suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in content_text)
            
            # Check for forms (potential phishing)
            forms = soup.find_all('form')
            has_forms = len(forms) > 0
            
            # Check for external links
            links = soup.find_all('a', href=True)
            external_links = 0
            for link in links:
                href = link['href']
                if href.startswith('http') and urlparse(href).netloc != urlparse(url).netloc:
                    external_links += 1
            
            return {
                'title': title_text,
                'description': description,
                'suspicious_keywords_count': suspicious_count,
                'has_forms': has_forms,
                'external_links_count': external_links,
                'total_links': len(links)
            }
        except:
            return {
                'title': '',
                'description': '',
                'suspicious_keywords_count': 0,
                'has_forms': False,
                'external_links_count': 0,
                'total_links': 0
            }

    def calculate_risk_score(self, url_data):
        """Calculate overall risk score"""
        risk_score = 0
        risk_factors = []
        
        # Domain analysis - prioritize malware domains
        if url_data['domain_info']['status'] == 'malware':
            risk_score += 60
            risk_factors.append("Known malware/testing domain")
        elif url_data['domain_info']['status'] == 'suspicious':
            risk_score += 30
            risk_factors.append("Suspicious domain/URL shortener")
        elif url_data['domain_info']['status'] == 'safe':
            risk_score -= 10
        
        # URL content analysis - check for malware-related keywords in URL
        url_lower = url_data['url'].lower()
        malware_keywords = ['eicar', 'malware', 'virus', 'trojan', 'exploit', 'payload', 'backdoor']
        if any(keyword in url_lower for keyword in malware_keywords):
            risk_score += 40
            risk_factors.append("URL contains malware-related keywords")
        
        # SSL Certificate
        if not url_data['ssl_info']['has_ssl']:
            risk_score += 25
            risk_factors.append("No SSL certificate")
        elif not url_data['ssl_info']['ssl_valid']:
            risk_score += 20
            risk_factors.append("Invalid SSL certificate")
        
        # Accessibility
        if not url_data['accessibility']['accessible']:
            risk_score += 15
            risk_factors.append("URL not accessible")
        elif url_data['accessibility']['redirects'] > 3:
            risk_score += 10
            risk_factors.append("Multiple redirects")
        
        # Content analysis
        if url_data['content'] and url_data['content'].get('suspicious_keywords_count', 0) > 2:
            risk_score += 20
            risk_factors.append("Contains suspicious keywords")
        
        if url_data['content'] and url_data['content'].get('has_forms', False):
            risk_score += 15
            risk_factors.append("Contains forms (potential data collection)")
        
        # Determine risk level
        if risk_score <= 10:
            risk_level = "Low"
        elif risk_score <= 30:
            risk_level = "Medium"
        elif risk_score <= 50:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            'score': max(0, min(100, risk_score)),
            'level': risk_level,
            'factors': risk_factors
        }

    def scan_url(self, url):
        """Main scanning function"""
        if not self.validate_url(url):
            return None
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Perform all checks
        accessibility = self.check_url_accessibility(url)
        ssl_info = self.check_ssl_certificate(url)
        domain_info = self.analyze_domain(url)
        content_info = self.analyze_content(url) if accessibility.get('accessible', False) else {
            'title': '',
            'description': '',
            'suspicious_keywords_count': 0,
            'has_forms': False,
            'external_links_count': 0,
            'total_links': 0
        }
        
        # Compile results
        results = {
            'url': url,
            'accessibility': accessibility,
            'ssl_info': ssl_info,
            'domain_info': domain_info,
            'content': content_info,
            'scan_time': datetime.now()
        }
        
        # Calculate risk score
        results['risk_assessment'] = self.calculate_risk_score(results)
        
        return results

# Initialize the scanner
@st.cache_resource
def get_scanner():
    return LinkGuard()

def main():
    scanner = get_scanner()
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Link Guard</h1>
        <p>Advanced URL Security Scanner & Threat Detection</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("🔍 Scan Options")
        
        # URL input
        url_input = st.text_input(
            "Enter URL to scan:",
            placeholder="https://example.com or example.com",
            help="Enter a complete URL or domain name"
        )
        
        scan_button = st.button("🔍 Scan URL", type="primary", use_container_width=True)
        
        st.markdown("---")
        
        # Features list
        st.header("🚀 Features")
        features = [
            "✅ URL Validation",
            "🌐 Accessibility Check",
            "🔒 SSL Certificate Analysis",
            "🏷️ Domain Reputation",
            "📄 Content Analysis",
            "⚠️ Risk Assessment",
            "🔄 Redirect Detection"
        ]
        
        for feature in features:
            st.markdown(f"• {feature}")
        
        st.markdown("---")
        st.markdown("**Made with ❤️ using Streamlit**")
    
    # Main content area
    if scan_button and url_input:
        with st.spinner("🔍 Scanning URL... Please wait"):
            results = scanner.scan_url(url_input)
            
            if results is None:
                st.error("❌ Invalid URL format. Please enter a valid URL.")
                return
            
            # Display results
            st.header("📊 Scan Results")
            
            # Risk assessment at the top
            risk = results['risk_assessment']
            risk_color = {
                'Low': 'safe-result',
                'Medium': 'warning-result',
                'High': 'danger-result',
                'Critical': 'danger-result'
            }
            
            st.markdown(f"""
            <div class="{risk_color[risk['level']]}">
                <h3>🎯 Risk Assessment: {risk['level']} ({risk['score']}/100)</h3>
                <p><strong>Scanned URL:</strong> {results['url']}</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Create columns for metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                status = "✅ Online" if results['accessibility']['accessible'] else "❌ Offline"
                st.metric("Status", status)
            
            with col2:
                ssl_status = "🔒 Secure" if results['ssl_info']['ssl_valid'] else "⚠️ Insecure"
                st.metric("SSL Status", ssl_status)
            
            with col3:
                domain_status = results['domain_info']['status'].title()
                st.metric("Domain Status", domain_status)
            
            with col4:
                response_time = results['accessibility'].get('response_time', 0)
                if response_time:
                    st.metric("Response Time", f"{response_time:.2f}s")
                else:
                    st.metric("Response Time", "N/A")
            
            # Detailed results in tabs
            tab1, tab2, tab3, tab4 = st.tabs(["🌐 Accessibility", "🔒 Security", "📄 Content", "⚠️ Risk Factors"])
            
            with tab1:
                st.subheader("Accessibility Analysis")
                acc = results['accessibility']
                
                if acc['accessible']:
                    st.success("✅ URL is accessible")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.info(f"**Status Code:** {acc['status_code']}")
                        st.info(f"**Response Time:** {acc['response_time']:.2f} seconds")
                    
                    with col2:
                        st.info(f"**Redirects:** {acc['redirects']}")
                        if acc['final_url'] != results['url']:
                            st.warning(f"**Final URL:** {acc['final_url']}")
                else:
                    st.error(f"❌ URL is not accessible: {acc.get('error', 'Unknown error')}")
            
            with tab2:
                st.subheader("Security Analysis")
                
                # SSL Information
                ssl = results['ssl_info']
                if ssl['has_ssl']:
                    if ssl['ssl_valid']:
                        st.success("✅ Valid SSL certificate")
                        if 'expiry_date' in ssl:
                            st.info(f"**Expires:** {ssl['expiry_date']}")
                    else:
                        st.error("❌ Invalid SSL certificate")
                else:
                    st.warning("⚠️ No SSL certificate (HTTP connection)")
                
                # Domain Information
                st.subheader("Domain Information")
                domain = results['domain_info']
                st.info(f"**Domain:** {domain['domain']}")
                st.info(f"**Status:** {domain['status'].title()}")
                
                if domain['creation_date']:
                    st.info(f"**Created:** {domain['creation_date']}")
            
            with tab3:
                st.subheader("Content Analysis")
                
                if results['content']:
                    content = results['content']
                    
                    if content['title']:
                        st.info(f"**Page Title:** {content['title']}")
                    
                    if content['description']:
                        st.info(f"**Description:** {content['description']}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Suspicious Keywords", content['suspicious_keywords_count'])
                        st.metric("Forms Detected", "Yes" if content['has_forms'] else "No")
                    
                    with col2:
                        st.metric("Total Links", content['total_links'])
                        st.metric("External Links", content['external_links_count'])
                else:
                    st.warning("Content analysis not available (URL not accessible)")
            
            with tab4:
                st.subheader("Risk Factors")
                
                if risk['factors']:
                    st.warning("⚠️ **Identified Risk Factors:**")
                    for factor in risk['factors']:
                        st.write(f"• {factor}")
                else:
                    st.success("✅ No significant risk factors identified")
                
                # Risk score breakdown
                st.subheader("Risk Score Breakdown")
                st.progress(risk['score'] / 100)
                
                risk_description = {
                    'Low': "The URL appears to be safe with minimal risk factors.",
                    'Medium': "The URL has some risk factors. Exercise caution.",
                    'High': "The URL has significant risk factors. Avoid if possible.",
                    'Critical': "The URL is highly suspicious. Do not visit."
                }
                
                st.write(risk_description[risk['level']])
            
            # Export results
            st.markdown("---")
            st.subheader("📥 Export Results")
            
            export_data = {
                'url': results['url'],
                'scan_time': results['scan_time'].isoformat(),
                'risk_level': risk['level'],
                'risk_score': risk['score'],
                'accessible': results['accessibility']['accessible'],
                'ssl_valid': results['ssl_info']['ssl_valid'],
                'domain_status': results['domain_info']['status']
            }
            
            st.download_button(
                label="📄 Download Scan Report (JSON)",
                data=json.dumps(export_data, indent=2),
                file_name=f"linkguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    elif not url_input and scan_button:
        st.warning("⚠️ Please enter a URL to scan.")
    
    # Information section
    if not scan_button:
        st.header("🛡️ About Link Guard")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="feature-card">
                <h4>🔍 Comprehensive URL Analysis</h4>
                <p>Link Guard performs multi-layer security analysis including accessibility checks, SSL certificate validation, domain reputation assessment, and content analysis to identify potential threats.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="feature-card">
                <h4>⚡ Real-time Scanning</h4>
                <p>Get instant results with our fast scanning engine that checks URLs against multiple security parameters and provides detailed risk assessments.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="feature-card">
                <h4>🎯 Risk Scoring</h4>
                <p>Our intelligent risk scoring system evaluates multiple factors to provide you with a clear understanding of the potential threats associated with any URL.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="feature-card">
                <h4>📊 Detailed Reports</h4>
                <p>Export comprehensive scan reports in JSON format for documentation, compliance, or further analysis of URL security assessments.</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.info("💡 **Tip:** Enter any URL in the sidebar to start scanning. Link Guard will analyze the URL's security, accessibility, and content to help you stay safe online.")

if __name__ == "__main__":
    main()
