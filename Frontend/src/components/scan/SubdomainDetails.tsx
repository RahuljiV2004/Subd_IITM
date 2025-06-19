import { useEffect,useState } from 'react';
import mapboxgl from "mapbox-gl";
import "mapbox-gl/dist/mapbox-gl.css";
import { useRef } from 'react';
import { RefreshCw } from "lucide-react";
import PDFDownloadButton from './PDFDownloadButton'
import { 
  X, 
  Globe, 
  Shield, 
  Server, 
  AlertTriangle, 
  Clock, 
  CheckCircle2, 
  AlertCircle, 
  XCircle, 
  Circle, 
  CircleDot, 
  CircleDashed 
} from 'lucide-react';
import type { Subdomain } from '@/types/subdomain';

interface SubdomainDetailsProps {
  subdomain: Subdomain;
  onClose: () => void;
}
  const latitude = 51.5074;
  const longitude = -0.1278;

  
export default function SubdomainDetails({ subdomain, onClose }: SubdomainDetailsProps) {
  // ✅ Put your own Mapbox Access Token here
   
  const mapContainer = useRef(null);
  const mapInstance = useRef(null);

  mapboxgl.accessToken = '';

    
  useEffect(() => {
    document.body.classList.add('modal-open');
    return () => document.body.classList.remove('modal-open');
  }, []);

  const getStatusIcon = (status: number) => {
    if (status >= 200 && status < 300) return <CheckCircle2 className="text-green-500" size={20} />;
    if (status >= 300 && status < 400) return <AlertCircle className="text-yellow-500" size={20} />;
    return <XCircle className="text-red-500" size={20} />;
  };



  const getSSLStatus = () => {
    if (subdomain.cert[0]) {
      return (
        <span className="flex items-center gap-1">
          <Shield className="text-green-500" size={16} />
          <span className="text-green-500">Secure</span>
        </span>
      );
    }
    return (
      <span className="flex items-center gap-1">
        <Shield className="text-red-500" size={16} />
        <span className="text-red-500">Insecure</span>
      </span>
    );
  };
  const [loading, setLoading] = useState(false);
  const handleClick = async () => {
    setLoading(true);
    try {
      const response = await fetch("http://localhost:5000/api/scan_subdomain", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
         body: JSON.stringify({ subdomain: subdomain.domain }),
      });

      const data = await response.json();
      console.log("Scan response:", data);
    } catch (error) {
      console.error("Error:", error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: number) => {
    if (status >= 200 && status < 300) {
      return (
        <span className="px-2 py-1 text-xs rounded-full bg-green-500/20 text-green-300 border border-green-500/30">
          {status}
        </span>
      );
    }
    if (status >= 300 && status < 400) {
      return (
        <span className="px-2 py-1 text-xs rounded-full bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">
          {status}
        </span>
      );
    }
    return (
      <span className="px-2 py-1 text-xs rounded-full bg-red-500/20 text-red-300 border border-red-500/30">
        {status}
      </span>
    );
  };
  const [ports, setPorts] = useState(subdomain.nmap?.open_ports || []);

  // ✅ On mount: if no open_ports, fetch once from DB
  useEffect(() => {
    if (!subdomain.nmap?.open_ports?.length) {
      fetchPorts();
    } else {
      // If you open another card with data, reset local state to prop
      setPorts(subdomain.nmap.open_ports);
    }
  }, [subdomain]);

  const fetchPorts = async () => {
    try {
      const res = await fetch(`http://127.0.0.1:5000/api/getPorts?subdomain=${subdomain.domain}`);
      const data = await res.json();
      setPorts(data.open_ports || []);
    } catch (err) {
      console.error("Error fetching ports:", err);
    }
  };
  const [refreshing, setRefreshing] = useState(false);

const refreshPorts = async () => {
  setRefreshing(true);
  try {
    await fetchPorts(); // or your fetch logic
  } catch (err) {
    console.error("Error refreshing:", err);
  } finally {
    setRefreshing(false);
  }
};

const [location, setLocation] = useState(null);

  // ✅ Fetch Lat/Lng from first IP
  useEffect(() => {
    const firstIP = subdomain.ip?.[0];
    if (firstIP) {
      const getLatLngFromIP = async (ip: string) => {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await response.json();
    const lat = data.lat;
    const lng = data.lon; // Note: ip-api uses 'lon' not 'lng'
    setLocation({ lat, lng });
  } catch (error) {
    console.error("Error fetching location:", error);
  }
};

      getLatLngFromIP(firstIP);
    }
  }, [subdomain]);

    // ✅ Initialize Map when location is available
  useEffect(() => {
    if (location && mapContainer.current && !mapInstance.current) {
      mapInstance.current = new mapboxgl.Map({
        container: mapContainer.current,
        style: "mapbox://styles/mapbox/streets-v11",
        center: [location.lng, location.lat],
        zoom: 8,
      });

      // ✅ Add marker
      new mapboxgl.Marker().setLngLat([location.lng, location.lat]).addTo(mapInstance.current);
    }
  }, [location]);

  return (
    <div className="modal-overlay " onClick={onClose}>
      <div className="modal-panel " onClick={e => e.stopPropagation()}>
        
<div className="modal-header flex items-center justify-between gap-4">
  {/* Domain name and Visit button group */}
  <div className="flex items-center gap-4 flex-grow overflow-hidden">
    <h2 className="modal-title font-mono text-2xl tracking-wider truncate">
      <span className="text-primary-70">&gt;</span> {subdomain.domain}
    </h2>
    <a
      href={`http://${subdomain.domain}`}
      target="_blank"
      rel="noopener noreferrer"
      className="text-base px-4 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary font-semibold hover:bg-primary/20 transition shrink-0"
    >
      Visit
    </a>
  </div>

  {/* Action buttons */}
  <div className="flex items-center gap-2 shrink-0">
    <button
      onClick={handleClick}
      disabled={loading}
      className={`text-base px-4 py-1.5 rounded-full border text-indigo-400 transition shrink-0
        ${loading 
          ? "bg-indigo-500/30 border-indigo-500/50 cursor-not-allowed" 
          : "bg-indigo-500/10 border-indigo-500/30 hover:bg-indigo-500/20"
        }`}
    >
      {loading ? (
        <span className="flex items-center gap-2">
          <svg
            className="animate-spin h-4 w-4 text-indigo-400"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            ></circle>
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8v8H4z"
            ></path>
          </svg>
          Running...
        </span>
      ) : (
        "Run Nmap Scan"
      )}
    </button>

    <button
      onClick={refreshPorts}
      disabled={refreshing}
      className={`text-base px-4 py-1.5 rounded-full border text-indigo-400 transition flex items-center gap-2 shrink-0
        ${refreshing
          ? "bg-indigo-500/30 border-indigo-500/50 cursor-not-allowed"
          : "bg-indigo-500/10 border-indigo-500/30 hover:bg-indigo-500/20"
        }`}
    >
      <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
      {refreshing ? "Refreshing..." : "Refresh Ports"}
    </button>

    <PDFDownloadButton subdomain={subdomain} />
  </div>

  {/* Close button */}
  <button className="modal-close shrink-0" onClick={onClose}>
    <X size={24} />
  </button>
</div>

        {/* <div className="modal-header">
         <div className="flex items-center gap-4">
  <h2 className="modal-title font-mono text-2xl tracking-wider">
    <span className="text-primary-70">&gt;</span> {subdomain.domain}
  </h2>
  <a
    href={`http://${subdomain.domain}`}
    target="_blank"
    rel="noopener noreferrer"
    className="text-base px-4 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary font-semibold hover:bg-primary/20 transition"
  >
    Visit
  </a>
  
  <button
      onClick={handleClick}
      disabled={loading}
      className={`text-base px-4 py-1.5 rounded-full border text-indigo-400 transition 
        ${loading ? "bg-indigo-500/30 border-indigo-500/50 cursor-not-allowed" : "bg-indigo-500/10 border-indigo-500/30 hover:bg-indigo-500/20"}`}
    >
      {loading ? (
        <span className="flex items-center gap-2">
          <svg
            className="animate-spin h-4 w-4 text-indigo-400"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            ></circle>
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8v8H4z"
            ></path>
          </svg>
          Running...
        </span>
      ) : (
        "Run Nmap Scan"
      )}
    </button>
    <button
    onClick={refreshPorts}
    disabled={refreshing}
    className={`text-base px-4 py-1.5 rounded-full border text-indigo-400 transition flex items-center gap-2 
      ${refreshing
        ? "bg-indigo-500/30 border-indigo-500/50 cursor-not-allowed"
        : "bg-indigo-500/10 border-indigo-500/30 hover:bg-indigo-500/20"}`}
  >
    <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
    {refreshing ? "Refreshing..." : "Refresh Ports"}
  </button>
 
  
  <PDFDownloadButton subdomain={subdomain} />
  
</div>
          <button className="modal-close" onClick={onClose}>
            <X size={24} />
          </button>
        </div> */}

        <div className="modal-content">

          <div className="modal-section">
            {/* <h3 className="modal-section-title text-green-500 text-xl font-bold">Basic Information</h3> */}
            <h3 className="modal-section-title text-green-500 text-xl font-bold ">
  &gt;&gt; Basic Information
</h3>


            <div className="modal-section-content">
              <div className="grid grid-cols-2 gap-4">
                <div className="modal-grid-item">
                  {/* <div className="modal-grid-label">Domain</div> */}
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Domain</div>

                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    <Globe className="text-primary-50" size={16} />
                    {subdomain.domain}
                  </div>
                </div>
                <div className="modal-grid-item">
                  {/* <div className="modal-grid-label">IP Addresses</div> */}
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">IP Address</div>

                  <div className="modal-grid-value text-primary flex flex-wrap gap-2">
                    {subdomain.ip.map((ip, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 text-xs rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30"
                      >
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="modal-section">
      <h3 className="modal-section-title text-green-500 text-xl font-bold">&gt;&gt; IP-Based Location</h3>
      <div className="modal-section-content">
        <div className="modal-grid-item">
          <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Location</div>
          {/* ✅ Container with reduced height */}
          <div
            ref={mapContainer}
            className="rounded border border-[#00FFFF] overflow-hidden"
            style={{ height: "200px", width: "100%" }}
          />
        </div>
      </div>
    </div>
          <div className="modal-section">
            <h3 className="modal-section-title text-green-500 text-xl font-bold">&gt;&gt; HTTP Status</h3>
            <div className="modal-section-content">
              <div className="grid grid-cols-2 gap-4">
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">HTTP Status</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    {getStatusIcon(subdomain.http[0])}
                    {getStatusBadge(subdomain.http[0])}
                    <span className="text-primary-50">{subdomain.http[1]}</span>
                  </div>
                </div>
                <div className="modal-grid-item">
                  {/* <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">HTTPS Status</div> */}
                  {/* <div className="modal-grid-label text-xl font-mono bg-black text-green-500 p-2 rounded">HTTPS Status</div> */}
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono ">
  HTTPS Status
</div>

                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    {getStatusIcon(subdomain.https[0])}
                    {getStatusBadge(subdomain.https[0])}
                    <span className="text-primary-50">{subdomain.https[2]}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
          

          
<div className="modal-section">
      <h3 className="modal-section-title text-green-500 text-xl font-bold">
        &gt;&gt; Open Ports
      </h3>

      <div className="modal-section-content">
        <div className="grid grid-cols-2 gap-4">
          <div className="modal-grid-item col-span-2">
            <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">
              Ports
            </div>

            <div className="modal-grid-value text-primary flex flex-wrap gap-2">
              {ports.length > 0 ? (
                ports.map((port) => (
                  <span
                    key={port}
                    className="px-2 py-1 bg-[#00FFFF]/10 border border-[#00FFFF] rounded text-[#00FFFF] text-sm"
                  >
                    {port}
                  </span>
                ))
              ) : (
                <span className="text-primary-50">
                  No Open Ports found
                </span>
              )}
            </div>

            
          </div>
        </div>
      </div>
    </div>

       
          <div className="modal-section">
            <h3 className="modal-section-title text-green-500 text-xl font-bold">&gt;&gt; SSL Certificate</h3>
            <div className="modal-section-content">
              <div className="grid grid-cols-2 gap-4">
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Status</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    {getSSLStatus()}
                  </div>
                </div>
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Expiry Date</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    <Clock className="text-primary-50" size={16} />
                    <span>{subdomain.cert[1]}</span>
                  </div>
                </div>
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Subject</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    <Globe className="text-primary-50" size={16} />
                    <span>{subdomain.cert_details.subject_common_name}</span>
                  </div>
                </div>
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Issuer</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    <Shield className="text-primary-50" size={16} />
                    <span>{subdomain.cert_details.issuer_common_name}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="modal-section">
            <h3 className="modal-section-title text-green-500 text-xl font-bold">&gt;&gt; Certificate Details</h3>
            <div className="modal-section-content">
              <div className="grid grid-cols-2 gap-4">
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Serial Number</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    <Circle className="text-primary-50" size={16} />
                    <span className="font-mono">{subdomain.cert_details.serial_number}</span>
                  </div>
                </div>
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Valid From</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    <Clock className="text-primary-50" size={16} />
                    <span>{subdomain.cert_details.valid_from}</span>
                  </div>
                </div>
                <div className="modal-grid-item">
                  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono" >Valid To</div>
                  <div className="modal-grid-value text-primary flex items-center gap-2">
                    <Clock className="text-primary-50" size={16} />
                    <span>{subdomain.cert_details.valid_to}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
         
<div className="modal-section">
  <h3 className="modal-section-title text-green-500 text-xl font-bold">
    &gt;&gt; Tech Stack (WhatWeb)
  </h3>
  <div className="modal-section-content">
    <div className="bg-black p-4 rounded-md text-gray-200 font-mono text-sm space-y-2 border border-gray-700 shadow-lg">
      {(() => {
        // Build cleaned entries only if they have values
        const entries = Object.entries(subdomain.whatweb?.plugins || {}).map(([pluginName, pluginData]) => {
          const extractValues = (obj) => {
            let results = [];
            for (const key in obj) {
              const val = obj[key];
              if (key === "string" && Array.isArray(val)) {
                results = results.concat(val);
              } else if (
                typeof val === "string" ||
                typeof val === "number" ||
                typeof val === "boolean"
              ) {
                results.push(val);
              } else if (typeof val === "object" && val !== null) {
                const keys = Object.keys(val);
                const isIndexed = keys.every(k => /^\d+$/.test(k));
                if (isIndexed) {
                  results = results.concat(Object.values(val));
                } else {
                  results = results.concat(extractValues(val));
                }
              }
            }
            return results;
          };

          const values = extractValues(pluginData).filter(v => v !== '' && v !== null && v !== undefined);
          return values.length ? { pluginName, valueText: values.join(', ') } : null;
        }).filter(Boolean);

        return entries.length ? (
          entries.map(({ pluginName, valueText }, i) => (
            <div key={i} className="flex flex-wrap">
              <span className="font-bold text-purple-400 mr-2">{pluginName}:</span>
              <span className="text-teal-300">{valueText}</span>
            </div>
          ))
        ) : (
          <span className="text-gray-500 italic">No plugins detected</span>
        );
      })()}
    </div>
  </div>
</div>


          <div className="modal-section">
  <h3 className="modal-section-title text-green-500 text-xl font-bold">&gt;&gt; DNSDumpster Details</h3>
  <div className="modal-section-content">
    <div className="grid grid-cols-2 gap-4">
      
      {/* A Records */}
      <div className="modal-grid-item">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">A Records</div>
        <div className="modal-grid-value text-primary flex flex-wrap gap-2 min-h-[1.5rem]">
          {subdomain.dnsdumpster?.a_records?.length ? (
            subdomain.dnsdumpster.a_records.map((record, i) => (
              <span
                key={i}
                className="px-2 py-1 text-xs rounded-full bg-teal-500/20 text-teal-300 border border-teal-500/30"
              >
                {record}
              </span>
            ))
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </div>
      </div>

      {/* MX Records */}
      <div className="modal-grid-item">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">MX Records</div>
        <div className="modal-grid-value text-primary flex flex-wrap gap-2 min-h-[1.5rem]">
          {subdomain.dnsdumpster?.mx_records?.length ? (
            subdomain.dnsdumpster.mx_records.map((record, i) => (
              <span
                key={i}
                className="px-2 py-1 text-xs rounded-full bg-teal-500/20 text-teal-300 border border-teal-500/30"
              >
                {record}
              </span>
            ))
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </div>
      </div>

      {/* You can add NS Records, CNAME Records, etc. the same way */}
      
    </div>
  </div>
</div>

<div className="modal-section">
  <h3 className="modal-section-title text-green-500 text-xl font-bold">&gt;&gt; MXToolbox Details</h3>
  <div className="modal-section-content">
    <div className="grid grid-cols-2 gap-4">

      {/* Domain Scanned */}
      <div className="modal-grid-item">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Domain</div>
        <div className="modal-grid-value text-primary">{subdomain.mxtoolbox?.commandArgument || '—'}</div>
      </div>

      {/* Time Recorded */}
      <div className="modal-grid-item">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Scan Time</div>
        <div className="modal-grid-value text-primary">{subdomain.mxtoolbox?.TimeRecorded || '—'}</div>
      </div>

      {/* Time To Complete */}
      <div className="modal-grid-item">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Scan Duration (ms)</div>
        <div className="modal-grid-value text-primary">{subdomain.mxtoolbox?.TimeToComplete+ "s" || '—'}</div>
      </div>

      {/* Reporting Name Server */}
      <div className="modal-grid-item">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Reporting NS</div>
        <div className="modal-grid-value text-primary">{subdomain.mxtoolbox?.ReportingNameServer || '—'}</div>
      </div>

      {/* Failures */}
     {/* Information */}

<div className="modal-grid-item col-span-2">
  <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Information</div>
  <div className="modal-grid-value text-primary flex flex-col gap-4">
    {Array.isArray(subdomain.mxtoolbox?.Information) && subdomain.mxtoolbox.Information.length > 0 ? (
      subdomain.mxtoolbox.Information.map((info, i) => (
        <div
          key={i}
          className="rounded-md border border-gray-700 bg-black p-4 text-sm font-mono text-gray-200 shadow-lg space-y-1"
        >
          <div><span className="font-bold text-purple-400">Type:</span> <span className="text-teal-300">{info.Type}</span></div>
          <div><span className="font-bold text-purple-400">Domain Name:</span> <span className="text-teal-300">{info["Domain Name"]}</span></div>
          <div><span className="font-bold text-purple-400">IP Address:</span> <span className="text-teal-300">{info["IP Address"]}</span></div>
          <div><span className="font-bold text-purple-400">TTL:</span> <span className="text-teal-300">{info.TTL}</span></div>
          <div><span className="font-bold text-purple-400">Status:</span> <span className="text-teal-300">{info.Status}</span></div>
          <div><span className="font-bold text-purple-400">Time:</span> <span className="text-teal-300">{info["Time (ms)"]}</span></div>
          <div><span className="font-bold text-purple-400">Auth:</span> <span className="text-teal-300">{info.Auth}</span></div>
          <div><span className="font-bold text-purple-400">Parent:</span> <span className="text-teal-300">{info.Parent}</span></div>
          <div><span className="font-bold text-purple-400">Local:</span> <span className="text-teal-300">{info.Local}</span></div>
          <div><span className="font-bold text-purple-400">ASN:</span> <span className="text-teal-300">{info.Asn}</span></div>
          <div><span className="font-bold text-purple-400">IPv6:</span> <span className="text-teal-300">{info.IsIPv6}</span></div>
        </div>
      ))
    ) : (
      <span className="text-muted-foreground">—</span>
    )}
  </div>
</div>




      {/* Timeouts */}
      <div className="modal-grid-item col-span-2">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Timeouts</div>
        <div className="modal-grid-value text-primary flex flex-wrap gap-2 min-h-[1.5rem]">
          {subdomain.mxtoolbox?.timeouts?.length ? (
            subdomain.mxtoolbox.timeouts.map((msg, i) => (
              <span
                key={i}
                className="px-2 py-1 text-xs rounded-full bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
              >
                {msg}
              </span>
            ))
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </div>
      </div>

      {/* Related Lookups */}
      <div className="modal-grid-item col-span-2">
        <div className="modal-grid-label text-[#BF40BF] text-lg font-mono">Related Lookups</div>
        <div className="modal-grid-value text-primary flex flex-col gap-1">
          {subdomain.mxtoolbox?.RelatedLookups?.length ? (
            subdomain.mxtoolbox.RelatedLookups.map((lookup, i) => (
              <a
                key={i}
                href={lookup.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-cyan-400 underline hover:text-cyan-300"
              >
                {lookup.Name}
              </a>
            ))
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </div>
      </div>

    </div>
  </div>
</div>


        </div>
      </div>
    </div>
  );
}
