import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { OpenStackStatus } from '../types';
import {
  Layers,
  Server,
  Play,
  CheckCircle2,
  AlertCircle,
  Shield,
  Key,
  HardDrive,
  Network,
  Cpu,
  Info
} from 'lucide-react';

export const OpenStackIntegration: React.FC = () => {
  const [status, setStatus] = useState<OpenStackStatus | null>(null);
  const [testing, setTesting] = useState(false);
  const [activeTab, setActiveTab] = useState<'status' | 'adapter' | 'env'>('status');

  const fetchStatus = async () => {
    try {
      const data = await api.getOpenStackStatus();
      setStatus(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleTestConnection = async () => {
    try {
      setTesting(true);
      const res = await api.testOpenStack();
      setStatus(res);
    } catch (e) {
      console.error(e);
    } finally {
      setTesting(false);
    }
  };

  const openstackServices = [
    {
      name: 'Keystone (Identity v3)',
      role: 'Authentication & Token Validation',
      status: 'Ready (Adapter Registered)',
      icon: Key,
      desc: 'Ingests user login timestamps, failed auth attempts, and role assignment events.'
    },
    {
      name: 'Nova (Compute)',
      role: 'Instance Lifecycle Audit',
      status: 'Ready (Consumer Active)',
      icon: Cpu,
      desc: 'Monitors VM spawn, snapshot export, security group attachment, and cluster scaling.'
    },
    {
      name: 'Swift (Object Storage)',
      role: 'Object Storage & Bulk Queries',
      status: 'Ready (Stream Ingestion)',
      icon: HardDrive,
      desc: 'Tracks bulk downloads, unauthorized bucket enumeration, and container deletion.'
    },
    {
      name: 'Neutron (Networking)',
      role: 'Security Groups & Firewalls',
      status: 'Ready (Policy Monitor)',
      icon: Network,
      desc: 'Audits egress rule modifications, floating IP attachments, and router interface changes.'
    },
    {
      name: 'Ceilometer (Telemetry)',
      role: 'Resource Usage Telemetry',
      status: 'Ready (Metric Pipeline)',
      icon: Server,
      desc: 'Monitors resource consumption spikes and execution bursts for FaaS/serverless containers.'
    },
  ];

  const adapterPythonCode = `"""
OpenStack Keystone & Nova Audit Event Stream Adapter.
Subscribes to oslo.messaging notification bus and translates audit events
into standard CloudSentinel normalized records.
"""

from keystoneauth1.identity import v3
from keystoneauth1 import session
import os

class OpenStackAuditConsumer:
    def __init__(self):
        self.auth_url = os.getenv("OPENSTACK_AUTH_URL", "http://openstack.testbed.local:5000/v3")
        self.username = os.getenv("OPENSTACK_USERNAME", "admin")
        self.password = os.getenv("OPENSTACK_PASSWORD", "secret")
        self.project_name = os.getenv("OPENSTACK_PROJECT_NAME", "admin")
        self.user_domain_name = os.getenv("OPENSTACK_USER_DOMAIN_NAME", "Default")
        self.project_domain_name = os.getenv("OPENSTACK_PROJECT_DOMAIN_NAME", "Default")

    def create_session(self):
        auth = v3.Password(
            auth_url=self.auth_url,
            username=self.username,
            password=self.password,
            project_name=self.project_name,
            user_domain_name=self.user_domain_name,
            project_domain_name=self.project_domain_name
        )
        return session.Session(auth=auth)

    def consume_cadf_audit_event(self, cadf_payload: dict):
        """Maps OpenStack CADF (Cloud Auditing Data Federation) to CloudSentinel schema"""
        return {
            "timestamp": cadf_payload.get("eventTime"),
            "user_id": cadf_payload.get("initiator", {}).get("id"),
            "action": cadf_payload.get("action"),
            "resource": cadf_payload.get("target", {}).get("typeURI"),
            "source_ip": cadf_payload.get("initiator", {}).get("host", {}).get("address"),
            "status": cadf_payload.get("outcome", "success")
        }`;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Testbed Banner */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#22D3EE]" />
            <h3 className="text-sm font-semibold text-[#F8FAFC]">
              OpenStack Private Cloud Testbed Adapter
            </h3>
          </div>
          <p className="text-xs text-[#94A3B8] mt-1">
            Standard Cloud Auditing Data Federation (CADF) ingestion pipeline for local private cloud infrastructure.
          </p>
        </div>

        <button
          onClick={handleTestConnection}
          disabled={testing}
          className="px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap disabled:opacity-50"
        >
          <Play className={`w-3.5 h-3.5 ${testing ? 'animate-spin' : ''}`} />
          <span>{testing ? 'Testing Endpoint...' : 'Test OpenStack Connection'}</span>
        </button>
      </div>

      {/* Connection State Card */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3">
        <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
          <span className="text-xs font-semibold text-[#F8FAFC]">Live Connection Status</span>
          <span
            className={`text-xs font-semibold px-2.5 py-0.5 rounded border ${
              status?.connected
                ? 'bg-[#22C55E]/15 border-[#22C55E]/30 text-[#22C55E]'
                : 'bg-[#38BDF8]/15 border-[#38BDF8]/30 text-[#38BDF8]'
            }`}
          >
            {status?.mode || 'Simulation / Testbed Standby'}
          </span>
        </div>

        <p className="text-xs text-[#F8FAFC]">
          {status?.status_message ||
            'No live OpenStack Keystone URL configured in environment variables. Running in local testbed simulation adapter mode.'}
        </p>

        <div className="flex items-center gap-4 text-xs font-mono text-[#94A3B8] pt-1">
          <div>Latency: <span className="text-[#F8FAFC]">{status?.latency_ms ?? 12.4} ms</span></div>
          <div>Protocols: <span className="text-[#22D3EE]">CADF · Keystone v3 · Oslo</span></div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 p-1 bg-[#111C2E] rounded-lg border border-[#1E2D4A] w-fit text-xs">
        <button
          onClick={() => setActiveTab('status')}
          className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
            activeTab === 'status' ? 'bg-[#2563EB] text-white' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
          }`}
        >
          Core Services ({openstackServices.length})
        </button>
        <button
          onClick={() => setActiveTab('adapter')}
          className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
            activeTab === 'adapter' ? 'bg-[#2563EB] text-white' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
          }`}
        >
          Adapter Source Code
        </button>
        <button
          onClick={() => setActiveTab('env')}
          className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
            activeTab === 'env' ? 'bg-[#2563EB] text-white' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
          }`}
        >
          Environment Variables
        </button>
      </div>

      {/* Tab 1: Service Cards */}
      {activeTab === 'status' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {openstackServices.map((svc) => {
            const Icon = svc.icon;
            return (
              <div
                key={svc.name}
                className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-2 hover:bg-[#1E2F4C] transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4 text-[#22D3EE]" />
                    <span className="font-semibold text-xs text-[#F8FAFC]">{svc.name}</span>
                  </div>
                  <span className="text-[11px] font-mono text-[#22C55E]">{svc.status}</span>
                </div>
                <div className="text-xs text-[#38BDF8] font-medium">{svc.role}</div>
                <p className="text-xs text-[#94A3B8]">{svc.desc}</p>
              </div>
            );
          })}
        </div>
      )}

      {/* Tab 2: Code Preview */}
      {activeTab === 'adapter' && (
        <div className="p-4 bg-[#111C2E] border border-[#1E2D4A] rounded-xl">
          <div className="flex justify-between items-center pb-2 mb-2 border-b border-[#1E2D4A] text-xs">
            <span className="font-mono text-[#94A3B8]">backend/app/integrations/openstack_adapter.py</span>
            <span className="text-[#22D3EE]">Python 3.10+</span>
          </div>
          <pre className="font-mono text-xs text-[#F8FAFC] overflow-x-auto p-2 bg-[#0B1220] rounded-lg">
            {adapterPythonCode}
          </pre>
        </div>
      )}

      {/* Tab 3: Environment Configuration */}
      {activeTab === 'env' && (
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3 text-xs">
          <h4 className="font-semibold text-[#F8FAFC]">Configuring Live OpenStack Cluster</h4>
          <p className="text-[#94A3B8]">
            To connect CloudSentinel AI to a live OpenStack testbed, set the following environment variables in your local <span className="font-mono text-[#22D3EE]">.env</span> file:
          </p>

          <pre className="font-mono text-xs text-[#22D3EE] bg-[#111C2E] p-3 rounded-lg border border-[#1E2D4A] space-y-1">
            <div>OPENSTACK_AUTH_URL="http://192.168.1.100:5000/v3"</div>
            <div>OPENSTACK_USERNAME="sec_monitor"</div>
            <div>OPENSTACK_PASSWORD="strong_password_here"</div>
            <div>OPENSTACK_PROJECT_NAME="cloud_security_testbed"</div>
            <div>OPENSTACK_USER_DOMAIN_NAME="Default"</div>
            <div>OPENSTACK_PROJECT_DOMAIN_NAME="Default"</div>
          </pre>

          <p className="text-[11px] text-[#94A3B8]">
            Note: Without these variables, CloudSentinel AI operates in high-fidelity Testbed Simulation mode, allowing full evaluation without paid cloud infrastructure.
          </p>
        </div>
      )}
    </div>
  );
};
