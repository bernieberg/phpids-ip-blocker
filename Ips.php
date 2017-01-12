<?php

/**
 * IDS_Ips
 *
 * Will log and allow you to block ip addresses 
 *
 * @category  Security
 * @author    Bernie Berg <bernie@dakotanetwork.com>
 * @license   http://www.gnu.org/licenses/lgpl.html LGPL
 * @version   Release: $Id:Ips.php 517 2011-07-29 15:04:13Z bernieberg $
 */
class IDS_Ips
{
	/**
     * Holds the data from the log file
     *
     * @var array
     */
	private $data = array();
	
	/**
     * how long an ip will be blocked from their last hit
     *
     * @var int
     */
	private $blocked_duration = 7200;
	
	/**
     * How many negative hits until they are blocked
     *
     * @var int
     */
	private $blocked_count = 5;
	
	/**
     * location of the ip log file
     *
     * @var string
     */
	private $ip_file = null;

	
	/**
     * Constructor
     *
     * Sets up the object with the passed arguments
     *
     * @param string $ip_file location of the ip log file
     * @param int $duration how long, in seconds, to keep an ip blocked
     * @param int $count how many hits until be block this ip
	 *
     * @return void
     */
    public function __construct($ip_file, $duration = FALSE, $count = FALSE) 
    {
		if($duration !== FALSE) $this->blocked_duration = $duration;
		if($count !== FALSE) $this->blocked_count = $count;
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
	
	/**
     * isBlocked
     *
     * Is the passed ip address blocked?
     *
     * @param string $ip_address ip we are checking
	 *
     * @return boolean
     */
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
	
	/**
     * unBlock
     *
     * remove the passed ip address, you should run  writeLog after this
     *
     * @param string $ip_address ip we are checking
	 *
     * @return void
     */
	public function unBlock($ip_address) 
    {
		if (array_key_exists($ip_address, $this->data)) {
			unset($this->data[$ip_address]);
		}
    }
	
	/**
     * logHit
     *
     * log and increment a negative hit for this ip address
     *
     * @param string $ip_address ip we are checking
	 *
     * @return void
     */
	public function logHit($ip_address) 
    {
		if (!array_key_exists($ip_address, $this->data)) {
			$this->data[$ip_address] = array($ip_address, 1, time());
		} else {
			$this->data[$ip_address][1]++; 
			$this->data[$ip_address][2] = time(); 
		}
    }
	
	/**
     * writeLog
     *
     * write the ip log file
	 *
     * @return void
     */
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