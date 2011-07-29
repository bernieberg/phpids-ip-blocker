<?php

class IDS_Ips
{
	private $data = null;
	private $blocked_duration = 7200;
	private $blocked_count = 5;
	private $ip_file = null;

    public function __construct($ip_file, $duration = 7200, $count = 5) 
    {
		$this->blocked_duration = $duration;
		$this->count = $count;
		$this->ip_file = $ip_file;
		
		if (!file_exists($ip_file)) {
			$this->data = array();
			return;
		}
		// 0 = ip address
		// 1 = count
		// 2 = last date
		
		$handle = fopen($ip_file, "r");
		$good_data = array();
		
		while (($data = fgetcsv($handle, 0, ",")) !== FALSE) {
		    $good_data[$data[0]] = $data;
		}
		fclose($handle);
		
		$this->data = $good_data;
    }
	
	public function isBlocked($ip_address) 
    {
		if (!array_key_exists($ip_address, $this->data)) {
			return false;
		}
		
		$blocked_time = time()-$this->blocked_duration;
		$ip_data = $this->data[$ip_address];
		
		if ($ip_data[1]>=$this->blocked_count && $ip_data[2]>=$blocked_time) {
			return true;
		}
		
		return false;
    }
	
	public function unBlock($ip_address) 
    {
		if (array_key_exists($ip_address, $this->data)) {
			unset($this->data[$ip_address]);
		}
		
		return true;
    }
	
	public function logHit($ip_address) 
    {
		if (!array_key_exists($ip_address, $this->data)) {
			$this->data[$ip_address] = array($ip_address, 1, time());
		} else {
			$this->data[$ip_address][1]++; 
			$this->data[$ip_address][2] = time(); 
		}
		
		return true;
    }
	
	public function writeLog() 
    {
		$fp = fopen($this->ip_file, 'w');

		foreach ($this->data as $fields) {
			fputcsv($fp, $fields);
		}

		fclose($fp);
		
		return true;
    }
}

?>