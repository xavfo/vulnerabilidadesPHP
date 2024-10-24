<?php

/**
 * Clase Scanengine
 * 
 * Una clase para escanear el estado del servidor Apache y aplicar reglas.
 */
class Scanengine
{
    /** @var array $currApacheRequests Un array para almacenar las solicitudes actuales al servidor Apache. */
    private array $currApacheRequests;

    /** @var string $apacheURL La URL de la página de estado del servidor Apache. */
    private string $apacheURL;

    /** @var array $scanRules Un array que contiene las reglas de escaneo. */
    private array $scanRules;

    /** @var array $scanActions Un array que contiene las acciones a tomar basadas en los resultados del escaneo. */
    private array $scanActions;

    /**
     * Constructor de Scanengine.
     * Inicializa las propiedades de la clase y establece los valores predeterminados.
     */
    public function __construct()
    {
        $this->currApacheRequests = array();
        $this->apacheURL = "http://localhost/server-status";

        $this->scanRules = array(
            "scripts" => function (array $currApacheRequests): void {
                echo PHP_EOL . "-- Análisis usando diccionario de cadenas de texto --" . PHP_EOL;

                // Carga la lista de términos y palabras a buscar en las URLs para el escaneo de peticiones sospechosas
                $scriptDictionary = file("scripts.txt", FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);

                if (!is_array($scriptDictionary)) {
                    echo "Hubo un error al leer scripts.txt, verifica si el archivo existe dentro de la carpeta raíz." . PHP_EOL;
                    return;
                }

                $hits = 0;

                foreach ($scriptDictionary as $id => $script) {
                    foreach ($currApacheRequests as $reqId => $request) {
                        if (str_contains($request["Request"], $script)) {
                            echo PHP_EOL . "Coincidencia encontrada para el script sospechoso '{$script}' en la solicitud '{$request["Request"]}' desde la IP {$request["Client"]}" . PHP_EOL;

                            $this->scanActions["firewallBlock"]($request["Client"]);
                            $hits++;
                        }
                    }
                }

                echo PHP_EOL . "Encontré {$hits} hit(s) en las peticiones analizadas." . PHP_EOL;
            },
            "IPHits" => function (array $currApacheRequests): void {

                // Escaneo de hits de IP
                $maxHits = 3;
                $IPHits = array();

                echo PHP_EOL . "-- Análisis de cantidad de hits por IP, Máximo {$maxHits} hit(s) --" . PHP_EOL;

                foreach ($currApacheRequests as $reqId => $request) {
                    if (!isset($IPHits[$request["Client"]])) {
                        $IPHits[$request["Client"]] = 1;
                    } else {
                        $IPHits[$request["Client"]]++;
                    }
                }

                $hits = 0;

                foreach ($IPHits as $ip => $hitsCount) {
                    if ($hitsCount > $maxHits) {
                        echo PHP_EOL . "Número de hits permitidos superado ({$maxHits}) desde la IP {$ip}" . PHP_EOL;
                        $this->scanActions["firewallBlock"]($ip);
                        $hits++;
                    }
                }

                echo PHP_EOL . "Encontré {$hits} hit(s) en las peticiones analizadas." . PHP_EOL;
            }
        );

        $this->scanActions = array(
            "firewallBlock" => function (string $clientIP): void {
                //No te golpees en la cara tu mismo.
                $arrIgnoreIps = array("127.0.0.1", "::1");

                if (!in_array($clientIP, $arrIgnoreIps)) {
                    echo "¡IP {$clientIP} agregada a la lista negra del firewall!" . PHP_EOL;
                }
            }
        );
    }

    /**
     * Establece la URL del estado del servidor Apache.
     * 
     * @param string $apacheURL La URL de la página de estado del servidor Apache.
     */
    public function setApacheURL(string $apacheURL): void
    {
        $this->apacheURL = $apacheURL;
    }

    /**
     * Recupera el estado del servidor Apache y analiza las solicitudes.
     * 
     * @return void
     */
    public function getApacheStatus(): void
    {
        $url = $this->apacheURL;

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($curl);

        if ($response === false) {
            echo 'Error de Curl: ' . curl_error($curl) . PHP_EOL;
            exit;
        }

        curl_close($curl);

        $dom = new DomDocument();
        @$dom->loadHTML($response);

        $tables = $dom->getElementsByTagName('table');
        $foundRequests = false;

        foreach ($tables as $table) {
            foreach ($table->attributes as $attr) {
                if ($attr->name == "border" && $attr->value == 0) {

                    echo "Lista de solicitudes encontrada en {$this->apacheURL}" . PHP_EOL;

                    $foundRequests = true;

                    $fieldHeaders = $table->getElementsByTagName('th');
                    $arrFieldKeys = array();

                    foreach ($fieldHeaders as $fieldHeader) {
                        $arrFieldKeys[] = $fieldHeader->nodeValue;
                    }

                    $requests = $table->getElementsByTagName('tr');

                    foreach ($requests as $req) {
                        $arrFields = array();
                        $fields = $req->getElementsByTagName('td');

                        if (count($fields) == 0) {
                            continue;
                        }

                        foreach ($arrFieldKeys as $key => $tag) {
                            $arrFields[$tag] = str_replace("\n", "", $fields->item($key)->nodeValue);
                        }

                        if (!empty($arrFields)) {
                            $this->currApacheRequests[] = $arrFields;
                        }
                    }
                }
            }

            if ($foundRequests) {
                break;
            }
        }

        if (!$foundRequests) {
            echo "Lista de solicitudes en {$this->apacheURL} no encontrada, ¿quizás una URL incorrecta?" . PHP_EOL;
        }
    }

    /**
     * Ejecuta controles basados en reglas en las solicitudes del servidor Apache.
     * 
     * @return void
     */
    public function checkRequests(): void
    {
        $this->scanRules["scripts"]($this->currApacheRequests);
        $this->scanRules["IPHits"]($this->currApacheRequests);
    }
}
